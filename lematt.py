#!/usr/bin/env python3

""" Maintain your LE infrastructure with config files and behaviors.

This was originally a shell script but got converted to python as
more conditions and exceptions became necessary.

lematt generates both rsa keys/certs AND ec keys/certs because modern systems
accept them all at once. You'll end up with two certs and two keys generated for
each input domain you configure.

Brief (very brief) overview of acronyms and terms:
    - LE: Let's Encrypt - CA issuing free DV certs, subject to rate limits
    - CA: Certificate Authority - an issuer/signer of certificates
    - DV: Domain Validated - just verifies you can control hosting and/or email
    - SAN: subjectAltName - how one certificate supports multiple domain names
    - SNI: Server Name Indication - TLS virtual hosting by giving clients SANs
    - TLS: Transport Layer Security - the "s" in "https" allowing encryption
    - UCC: Unified Communications Certificate - X.509 TLS certificate with SANs
    - X.509: an archaic, but sadly universal, file format for certificates
    - CSR: Certificate Signing Request - how CAs sign public keys and domains
    - PEM: "Privacy-Enhanced E-Mail" - a file format for base64 encoded data
    - RSA: historically standard Internet-wide public key encryption system
    - EC: Elliptic Curve - a more modern public key encryption system
    - OCSP: Online Certificate Status Protocol - realtime CRL; signed responses
    - Staple: include CA-signed OCSP status with your cert when clients connect
    - CRL: Certificate Revocation List - a way to check if certs are revoked
"""

import multiprocessing
import configparser
import collections
import subprocess
import itertools
import argparse
import datetime
import pathlib
import socket
import json
import time
import ssl
import sys
import os

import acme_tiny  # distributed with lematt
from datetime import timedelta  # make some lines shorter

MIN_VERSION = (3, 6)
if sys.version_info < MIN_VERSION:
    # Why only 3.6 or later? 3.6 introduced F-strings we
    # use for f"hello {var}" formatting everywhere.
    # Sure, we could have used one of the other 20 kinds of
    # python string formatting methods, but we didn't.
    print("Sorry, lematt requires Python 3.6 or later.")
    sys.exit(1)


def log(what, mode="", update=False):
    # If requesting more than just a newline separator...
    if what:
        if IS_TEST:
            prefix = "[TEST] "
        else:
            prefix = "> "
    else:
        prefix = ""

    if mode:
        mode = f"[{mode}]"

    if not IS_CRON or update:
        print(f"{prefix}{mode} {what}")


def getSubdir(subdir):
    if IS_TEST:
        base = "test/"
    else:
        base = "prod/"

    return base + subdir


def loadDomainActions():
    """Read actions.conf and parse actions into usable dicts."""
    domainActions = {}
    domainActionNames = {}
    updaters = configparser.ConfigParser()
    updaters.read(f"{configBase}/actions.conf")

    def extractAndPopulate(sectionName, override, actions):
        if sectionName in override:
            commands = json.loads(override[sectionName])
            actions[sectionName] = commands

    defaultOCSP = False
    if "ocspStapleRequired" in updaters["default"]:
        defaultOCSP = updaters["default"]["ocspStapleRequired"]

    def errIfIn(what, things, sect):
        if what in things:
            print(f"Error: '{what}' entry not allowed in section [{sect}]")
            sys.exit(1)

    # Usage sanity check
    for uda in ["default", "every"]:
        preActions = updaters[uda]
        errIfIn("domains", preActions, uda)

        if uda == "every":
            errIfIn("ocspStapleRequired", preActions, uda)

    # Use ConfigParser magic to make a global dict 'default' for this key
    # so we don't have to guard "if val in dict" everywhere.
    updaters["DEFAULT"] = {"ocspStapleRequired": defaultOCSP}

    # Use '.sections()' here because if we iterate 'updaters' directly,
    # we get the meta 'DEFAULT' key which we don't want to process.
    # '.sections()' only returns user-created sections.
    for uda in updaters.sections():
        preActions = updaters[uda]
        actions = {"actionName": uda}
        domainActionNames[uda] = actions

        if not (uda == "default" or uda == "every"):
            # If not in the default section, get domains this override
            # should apply towards.
            domains = preActions["domains"].split()

        # Extract override sections present (all optional)
        extractAndPopulate("prepare", preActions, actions)
        extractAndPopulate("update", preActions, actions)
        extractAndPopulate("uploadCerts", preActions, actions)
        extractAndPopulate("uploadKeys", preActions, actions)

        # Irrelevant for section 'every', but no harm done:
        actions["ocspStapleRequired"] = preActions.getboolean("ocspStapleRequired")

        # If default section, populate default domainActions
        if uda == "default" or uda == "every":
            domainActions[uda] = actions
        else:
            # else, attach actions to each domain inside this override
            for domain in domains:
                # log(f"Populating exceptions for {domain} as: {actions}")
                domainActions[domain] = actions

    return domainActions, domainActionNames


def gendir(subname):
    """Create a directory hierarchy but don't complain if already exists"""
    adir = pathlib.Path("{}/{}".format(configBase, subname))
    adir.mkdir(parents=True, exist_ok=True)


def run(thing, shell=False, output=True, stdinSend=None):
    """Run any string as a command (maybe as shell for env/expansion too)"""
    log(f"Running: {thing}", "CMD", update=True)
    if stdinSend:
        # use 'repr' because we want to print the string with visible \n
        # instead of exploding the formatted string across ten lines
        log(f"WITH STDIN: {repr(stdinSend)}", "CMD", update=True)

    # If running with shell=True, command must be a single string
    # the shell itself will parse and do glob expansion, etc.
    # If running with shell=False, command must be a list of strings
    # where command[0] is the executable and command[1:] will be
    # the command's argv array.
    command = thing
    if not shell:
        command = thing.split()

    return subprocess.run(
        command,
        check=output,
        shell=shell,
        input=stdinSend.encode() if stdinSend else None,
        # note: we could use 'text=True' here to avoid .encode(),
        #       but text=True is only Python 3.7 and as of right now we
        #       work fine in Python 3.6. Seems adding one line invaliding
        #       our entire current Python version is a bit extreme.
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def runAsync(thing, shell=False):
    log(f"Running: {thing}", "CMD-ASYNC", update=True)

    command = thing
    if not shell:
        command = thing.split()

    return subprocess.Popen(command, shell=shell)


def runAndWrite(thing, writeTo, perm=0o644, shell=False, stdinSend=None):
    ran = run(thing, shell=shell, stdinSend=stdinSend)

    # Python doesn't have a clean way of opening files with
    # pre-determined file permissions, so we get to do this instead...
    with os.fdopen(os.open(writeTo, os.O_WRONLY | os.O_CREAT, perm), "w") as w:
        w.write(ran.stdout.decode("utf-8"))


def customizeName(subdir, name, subtype, enctype, ext="pem"):
    assert enctype == "rsa" or enctype == "ec"

    return "{}/{}/{}-{}.{}{}.{}".format(
        configBase,
        getSubdir(subdir),
        name,
        subtype,
        RSA_TAG if enctype == "rsa" else CURVE_TAG,
        ".test" if IS_TEST else "",
        ext,
    )


def generateCSR(privateKey, domains, outfile):
    useSAN = len(domains) > 1

    def needsOCSP():
        def required(domain):
            if domain in domainActions:
                return domainActions[domain]["ocspStapleRequired"]

            return domainActions["default"]["ocspStapleRequired"]

        # do a quick loop to make sure all SAN domains have
        # the same 'ocspStapleRequired' value.
        # Since OCSP is a value of the entire certificate, we can't
        # mix and match domain configs and OCSP values.
        # Mixing can be dangerous because some servers don't staple,
        # but if the cert requires it, the service would be unusable
        # (i.e. dovecot and postfix don't staple, but nginx does)
        hasOCSP = required(domains[0])
        for domain in domains[1:]:
            if required(domain) != hasOCSP:
                print("Error: All SAN domains don't have the same OCSP config!")
                print(f"Verify all domains have same OCSP settings: {domains}")
                sys.exit(1)

        return hasOCSP

    subjectAltNames = ""
    cmdSAN = ""
    if useSAN:
        # Assemble list of all domains (including the primary CN) for SANing
        altNames = [f"DNS:{domain}" for domain in domains]
        subjectAltNames = ",".join(altNames)
        cmdSAN = "-reqexts SAN"

    # Use first domain as the primary common name
    domain = domains[0]

    ocspRequired = ""
    if needsOCSP():
        ocspRequired = "1.3.6.1.5.5.7.1.24 = DER:30:03:02:01:05"
        # openssl >= 1.1 supports the cleaner syntax below instead of OIDs,
        # but we can't guarantee most users have a compatible version yet:
        # ocspRequired = "tlsfeature = status_request"

    # Mock an in-line config real quick...
    # This is a bit weird because openssl doesn't support alt names
    # on the command line — it only supports them by reading a file
    # or by reading from stdin, so we mock a config file on stdin
    # for openssl to parse.
    #
    # If you're curious about the contents of the CSR itself, re-create the
    # generated command line with a given stdin and append -text to get
    # a human text representation of the CSR.
    runAndWrite(
        f"openssl req -new -sha256 -key {privateKey} -subj /CN={domain} "
        f"{cmdSAN} -config -",
        outfile,
        stdinSend=f"""[req]
distinguished_name=req_dn

[req_dn]

[v3_req]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment
{ocspRequired}

[SAN]
subjectAltName={subjectAltNames}""",
    )


def generateCSRSingleDomain(privateKey, domain, outfile):
    assert isinstance(domain, str)
    generateCSR(privateKey, [domain], outfile)


def generateCSRWithSAN(privateKey, domains, outfile):
    assert isinstance(domains, list)
    generateCSR(privateKey, domains, outfile)


# unused, but may be useful in the future
def certFromNetwork(hostname):
    """Get cert expiration against a live server"""
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )

    conn.settimeout(3)

    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    conn.close()

    assert isinstance(ssl_info, dict)
    return ssl_info


def certFromFile(certPath):
    """Get cert expiration from local file"""
    # If cert doesn't exist, it must be requested...
    certExists = os.path.isfile(certPath)
    if not certExists:
        return True

    # This is an internal Python API. Not guaranteed to exist across releases.
    certDetails = ssl._ssl._test_decode_cert(certPath)

    assert isinstance(certDetails, dict)
    return certDetails


def certNeedsRenewal(certDetails, utcnow):
    # The first check guards against True from 'certFromFile()'.
    # (if cert doesn't exist, we obviously need to request one)
    if not isinstance(certDetails, dict):
        return True

    def timeRemaining(expires):
        return expires - utcnow

    def needsRenewNow(expires):
        remaining = timeRemaining(expires)

        if remaining < timedelta(days=0):
            # cert has already expired!
            return True

        if remaining < REAUTHORIZE_DAYS_IN_ADVANCE:
            return True

        return False

    # Future - Past (now), ideally
    ssl_date_fmt = r"%b %d %H:%M:%S %Y %Z"

    expirationAsDate = datetime.datetime.strptime(certDetails["notAfter"], ssl_date_fmt)

    return needsRenewNow(expirationAsDate)


def requestCert(csr, outCert, isTest=False):
    if isTest:
        directory = STAGING
    else:
        directory = PRODUCTION

    # This is where we can plug in different cert request methods.
    # Right now we just pulled in acme_tiny which is a simple
    # http-01 wrapper around openssl subprocesses.
    # We can add dns-01 fairly easily if we add a way to injest
    # DNS API credentials then integrate with both DNS APIs themselves
    # (can easily adapt from other LE requesting systems) then
    # send acme dns-01 requests to LE too.
    try:
        signedCert = acme_tiny.get_crt(
            ACCOUNT_KEY, csr, CHALLENGE_DIR, directory_url=directory
        )
    except Exception as e:
        print("FAILED FOR DOMAIN:", csr, "BECAUSE", e)
        return

    if False and concurrency > 2:
        # Acme doesn't like too-aggressive attempts
        time.sleep(0.5)

    with open(outCert, "w") as writeMe:
        writeMe.write(signedCert)


def prepareDomainForUpdate(domain):
    if domain in domainActions:
        actions = domainActions[domain]
    else:
        actions = domainActions["default"]

    if "every" in domainActions:
        allActions = domainActions["every"]
    else:
        allActions = []

    def prepare(acts):
        return [runAsync(X.replace("DOMAIN", domain)) for X in acts["prepare"]]

    prepared = []
    if "prepare" in actions:
        prepared.extend(prepare(actions))

    if "prepare" in allActions:
        prepared.extend(prepare(allActions))

    return prepared


def prepareDomainsForUpdate(domains):
    prepared = []
    for domain in domains:
        prepare = prepareDomainForUpdate(domain)
        if prepare:
            prepared.extend(prepare)

    return prepared


def unprepareDomainForUpdate(prepared):
    if prepared:
        for prepare in prepared:
            prepare.kill()

        # Why does printing stdout from Popen cause our
        # terminal session to go all weird?
        # Reset terminal semantics...
        try:
            run("stty sane")
        except BaseException:
            # This may not work if run detatched
            # from a shell (like via cron)? Just ignore any
            # stty failures.
            pass


def generateKeysAndCertsAndRequestSignedCerts(configuredDomain, domainActions, keyType):
    # Now do the cert update (or cert generation, along with key generation) for
    # both RSA and EC keys:
    updatedCerts = {}

    # Use timestamp for detecting expired certs or certs needing renewal soon
    utcnow = datetime.datetime.utcnow()

    def updateDomainForKeyType(domain, keyType):
        # If this is a SAN request, combine all domains for filenames
        if isinstance(domain, list):
            # Do our best to preserve the order of SAN domains even
            # if they change.
            # Otherwise, if the order gets rearranged, we would generate
            # entirely new keys and certs even though they cover the
            # same set of domains.
            # Basically: convert SANs into a set, sort it, use that as
            # filename appended to the CN name for persisting set uniqueness.
            deduplicatedSANs = list(set(domain[1:]))
            deduplicatedSANs.sort(key=sortByDomain)
            deduplicatedSANs.insert(0, domain[0])
            domains = deduplicatedSANs
            domain = "_".join(domains)  # "_" <-- eyelashes bot supreme
        else:
            domains = []

        assert "." in domain, f"Domain ({domain}) isn't a domain name?"
        privateKey = customizeName("key", domain, "key", keyType)
        cert = customizeName("cert", domain, "cert-combined", keyType)
        csr = customizeName("csr", domain, "csr", keyType, "csr")
        isEC = keyType == "ec"

        def generateKey():
            """Either: use key if exists or create new if requested"""
            if ALWAYS_NEW_KEYS or not os.path.isfile(privateKey):
                if isEC:
                    log(f"Generating EC {CURVE} key...", keyType)
                    runAndWrite(
                        "openssl ecparam -genkey -name {}".format(CURVE),
                        privateKey,
                        0o600,
                    )
                else:
                    log(f"Generating RSA {KEYBITS_RSA} key...", keyType)
                    runAndWrite(
                        "openssl genrsa {}".format(KEYBITS_RSA), privateKey, 0o600
                    )

                # also link the combined key into symlinks for each domain
                # the key represents for easier configuration management...
                for d in domains:
                    singleDomainKey = customizeName("key", d, "key", keyType)

                    # remove if exists, then we re-create immediately after
                    try:
                        os.unlink(singleDomainKey)
                    except:
                        pass

                    keyNameOnly = os.path.basename(privateKey)
                    log(
                        f"Linking {keyNameOnly} to {singleDomainKey}",
                        keyType,
                        update=True,
                    )
                    os.symlink(keyNameOnly, singleDomainKey)

        def generateCSR_():
            """Either: use CSR if exists or create new if requested"""
            if ALWAYS_NEW_KEYS or not os.path.isfile(csr):
                log("Generating CSR...", keyType)
                if domains:
                    generateCSRWithSAN(privateKey, domains, csr)
                else:
                    generateCSRSingleDomain(privateKey, domain, csr)

        log(f"Checking certificate for {domain}...", keyType)

        if not certNeedsRenewal(certFromFile(cert), utcnow):
            log("Not renewing!", keyType)
            return

        log(f"Renewing {domain}!", keyType, update=True)

        generateKey()
        generateCSR_()

        if domains:
            prepared = prepareDomainsForUpdate(domains)
        else:
            prepared = prepareDomainForUpdate(domain)

        requestCert(csr, cert, IS_TEST)

        # Also create individually named symlinks for each domain pointing
        # back to the primary bundle where it originates.
        # (makes adding/removing domains from SAN certs easier since each
        #  addition or removal completely changes the combined cert name, which
        #  then requires a full reconfig of everywhere they are used, but if we
        #  use symlinks to the bundles, we can add/remove certs without reconfig)
        for d in domains:
            singleDomainCert = customizeName("cert", d, "cert-combined", keyType)

            # remove if exists, then we re-create immediately after
            try:
                os.unlink(singleDomainCert)
            except:
                pass

            certNameOnly = os.path.basename(cert)
            log(f"Linking {certNameOnly} to {singleDomainCert}", keyType, update=True)
            # symlink from single FILE IN DIR to SINGLE FILE IN DIR
            # (i.e. don't smlink the full absolute path in lematt/conf/prod/cert/...)
            os.symlink(certNameOnly, singleDomainCert)

        unprepareDomainForUpdate(prepared)

        # NOTE: if you have DUPLICATE certificates like a single
        #       domain certificate with the same in another cert's SANs,
        #       you will trigger actions for whichever domain is processed last.
        # e.g.
        #       mail.mysite.com
        #       mysite.com mail.mysite.com
        # The above would generate keys and certs for mail.mysite.com twice
        # (with the second key being on the SAN cert of mysite.com),
        # but your triggered actions would deliver mysite.com* keys and certs
        # to mail.mysite.com.
        if domains:
            # attach all domains to our update dict so we can report on why
            # update actions are happening per-domain

            # We use tuples here because tuples can be members of
            # sets, which lets us easily deduplicate repeated SAN-vs-CN
            # mappings later (lists can't be members of sets).
            for d in domains:
                updatedCerts[d] = tuple(domains)
        else:
            updatedCerts[domain] = tuple([domain])

    assert keyType == "rsa" or keyType == "ec", f"Invalid keyType {keyType}!"

    updateDomainForKeyType(configuredDomain, keyType)
    log("")  # visually break with a newline between processed domains

    return updatedCerts


def sortByDomain(x):
    # Sort domain names by their top-down sort order, but ignore actual TLD.
    # e.g. mail.hello.there.com will get a sort tuple of:
    #      (there hello mail)
    parts = x.split(".")
    parts.reverse()
    return tuple(parts[1:])


# 'domainActions' is a map of domain names -> action description maps
# 'domainActionNames' is a map of action names -> action description maps
# action maps have element 'actionName' to map domainActions->domainNameActions
# for deduplicating final cert/key copying and update actions.
def updateKeysAndCertsAndServices(domainActions, domainActionNames, updatedCerts):

    # No updated certs? No need to update anything!
    if not updatedCerts:
        return

    # If certs were updated, run their associated update actions...
    def runUploadsAndUpdates(updatedDomains, actions):
        assert isinstance(actions, dict)

        firstDomains = []

        # We only copy keys/certs based on the CN name which is ud[0]
        for ud in updatedDomains:
            firstDomains.append(ud[0])

        # We want to run ALL replaces and ONE update at the end
        # in aggregated/combined/unified commands instead of running
        # N copies and N updates if we were processing all cert updates
        # individually.
        replaceCert = " ".join(
            [
                f"{configBase}/{getSubdir('cert')}/{ud}*"
                for uds in updatedDomains
                for ud in uds
            ]
        )
        replaceKey = " ".join(
            [
                f"{configBase}/{getSubdir('key')}/{ud}*"
                for uds in updatedDomains
                for ud in uds
            ]
        )

        replaceDomainsCN = " ".join(firstDomains)

        # Flatten the 'updatedDomains' list of lists so we can just join it all
        replaceDomainsALL = " ".join(set(itertools.chain(*updatedDomains)))

        # This loop basically flattens nested updatedDomains and annotates
        # which ones are SAN domains versus the root CN itself
        totalDomainsSANDescribed = []

        updatedDomains = list(updatedDomains)
        updatedDomains.sort(key=lambda x: sortByDomain(x[0]))

        # Generate informative output during the final action reporting phase
        for ud in updatedDomains:
            if len(ud) > 1:
                place = [ud[0]]
                place.extend([f"{u} (SAN)" for u in ud[1:]])
                place = ", ".join(place)
                place = f"({place})"
            else:
                place = ud[0]
            totalDomainsSANDescribed.append(place)

        updatedFormatted = ", ".join(totalDomainsSANDescribed)
        log(
            "Executing " f"[{actions['actionName']}] for {updatedFormatted}",
            "action",
            update=True,
        )

        # Do we have upload cert overrides?
        if "uploadCerts" in actions:
            for upload in actions["uploadCerts"]:
                run(upload.replace("CERTS", replaceCert), shell=True)

        # Do we have upload key overrides?
        if "uploadKeys" in actions:
            for upload in actions["uploadKeys"]:
                run(upload.replace("KEYS", replaceKey), shell=True)

        # Now with certs/keys replaced, run full service update:
        if "update" in actions:
            for action in actions["update"]:
                action = action.replace("DOMAINS_CN", replaceDomainsCN)
                action = action.replace("DOMAINS_ALL", replaceDomainsALL)
                run(action, shell=True)

    # 'combinedProcessingResult' is a map of:
    # actionNames -> set of domains for action
    # We use a set because with SAN domains, each SAN name has the full
    # domain set for the entire cert, but we only care about each
    # unique grouping.
    combinedProcessingResult = collections.defaultdict(set)

    # deduplicate actions across all domains so we only do one update
    # action across all updated certs this round.
    # print(updatedCerts)

    # Do we have 'every' actions for post-processing?
    hasGlobalEveryActionGroup = "every" in domainActionNames

    for updatedDomain, domainsOnCert in updatedCerts.items():
        # Step 1: Lookup domain in map of DOMAIN->Actions
        # Step 2: Get Action Name from map
        # Step 3: Append domain to list in map of ActionName->[Domains]
        # Step 4: Run each action on each aggregated domain list

        # For SAN domains, we need to trigger SAN overrides too, but provide
        # the key+cert starting with sniDomains[0] which probably isn't
        # the SAN name itself...
        # So, we need to map SAN actions back to actual cert names, which we
        # accomplish by just using the entire domain list per cert and using
        # the [0]th entry as the CN and the rest are alt names.

        # print(updatedDomain, domainActions, domainActionNames)
        # If this domain has an explicit override:
        if updatedDomain in domainActions:
            actions = domainActions[updatedDomain]
            actionName = actions["actionName"]
            combinedProcessingResult[actionName].add(domainsOnCert)
        else:  # else, no override, so use default action!
            combinedProcessingResult["default"].add(domainsOnCert)

        if hasGlobalEveryActionGroup:
            combinedProcessingResult["every"].add(domainsOnCert)

    # Now run deduplicated domain actions for uploads and service updates:
    if combinedProcessingResult:
        log("Copying keys and certs then reloading services...", "action", update=True)

    # print(combinedProcessingResult)
    for sectionName, sectionDomains in combinedProcessingResult.items():
        runUploadsAndUpdates(sectionDomains, domainActionNames[sectionName])
        log("", update=True)  # line break


def loadDomains():
    # Format of 'domains' file is one or more domains per line.
    # Each line becomes ONE certificate. If more than one domain
    # is present, an SAN certificate will be generated.
    # If the secondary domains on a line don't have a '.', they will
    # be prepended to the first domain on the line.
    # e.g. "mydomain.com www" will generate a certificate with
    # domains: mydomain.com and www.mydomain.com
    configuredDomains = []
    with open(f"{configBase}/domains", "r") as doms:
        for line in doms:
            # Skip commented out or blank lines
            if line.startswith("#") or line.startswith("\n"):
                continue

            # If multiple names are on one line, they all become
            # one SAN certificate
            domainsOnLine = line.split()
            firstDomain = domainsOnLine[0]

            # All rate limits detailed at:
            # https://letsencrypt.org/docs/rate-limits/
            if len(domainsOnLine) > 100:
                print(
                    f"Error! The domain limit is 100 per certificate, but you "
                    "configured {len(domainsOnLine)} domains:\n{domainsOnLine}"
                )
                sys.exit(1)

            # If only one domain, present as a string, _not_ a list,
            # so the rest of our code knows not to populate SAN fields
            if len(domainsOnLine) == 1:
                domainsOnLine = firstDomain
            else:
                # else, format domains where required
                for i, domain in enumerate(domainsOnLine):
                    # you can use subdomains as shorthand by just giving their
                    # name and we take care of appending the first
                    # domain on the line to your subdomain
                    if "." not in domain:
                        domainsOnLine[i] = f"{domain}.{firstDomain}"

            configuredDomains.append(domainsOnLine)

    return configuredDomains


if __name__ == "__main__":
    # Rate limits described at:
    # Testing / Staging: https://letsencrypt.org/docs/staging-environment/
    #        Production: https://letsencrypt.org/docs/rate-limits/
    parser = argparse.ArgumentParser(description="Matt's Let's Encrypt Automation")

    # production-xor-staging/testing
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--prod",
        dest="isTest",
        action="store_false",
        help="Use LE production endpoint. "
        "Production rate limit is 5 duplicate certs per domain per week.",
    )

    group.add_argument(
        "--test",
        dest="isTest",
        action="store_true",
        help="""Use LE staging endpoint.
        Keys and certs will have 'test' in filenames.
        Don't waste your production rate limits during testing.
        Staging rate limit is 30,000 cert requests per week and
        30,000 duplicate cert issuance per week (per domain).""",
    )

    parser.add_argument(
        "--cron",
        dest="isCron",
        action="store_true",
        help="Only produce output when changes happen.",
    )

    parser.add_argument(
        "--parallel",
        dest="concurrency",
        default=1,
        type=int,
        help="Number of certificates to process in parallel",
    )

    parser.add_argument(
        "--config",
        dest="config",
        default="conf/lematt.conf",
        help="Path to your lematt.conf - "
        "config files 'domains' and 'actions.conf' "
        "must be in the same directory as lematt.conf",
    )

    args = parser.parse_args()

    IS_CRON = args.isCron
    IS_TEST = args.isTest

    concurrency = args.concurrency

    configBase = os.path.dirname(os.path.realpath(args.config))

    conf = configparser.ConfigParser()
    conf["DEFAULT"] = {
        "reauthorizeDays": 15,
        "keyBitsRSA": "2048",
        "alwaysGenerateNewKeys": "no",
        "generateNewCertsAfterDays": 0,
        "curve": "prime256v1",
    }

    if not conf.read(args.config):
        print(f"Requested config path not found: {args.config}")
        sys.exit(1)

    config = conf["config"]

    # We treat these as globals throughout the code, so they must
    # be initialized here outside of any functions:
    reauthDays = float(config["reauthorizeDays"])
    REAUTHORIZE_DAYS_IN_ADVANCE = timedelta(days=reauthDays)
    CHALLENGE_DIR = config["challengeDropDir"]
    ACCOUNT_KEY = config["accountKey"]
    KEYBITS_RSA = config["keyBitsRSA"]
    CURVE = config["curve"]
    ALWAYS_NEW_KEYS = config.getboolean("alwaysGenerateNewKeys")
    GENERATE_CERTS_DAYS = float(config["generateNewCertsAfterDays"])

    if GENERATE_CERTS_DAYS:  # <-- if !0
        # Instead of days-before-expire, use days-since-issue math.
        # Maximum rate should be 3.5 days-since-issue because:
        # Fun Fact: LE gives 90 day certs, but you get 5 duplicates per week.
        # Since we are issuing both RSA and EC certs, each issue eats
        # 2 rate limits out of 5 in every 7 day sliding window.
        # Remaining under rate limit of 5 per week means we can
        # run a complete issue cycle twice a week, giving us a
        # period for issuing of 7 days / 2 runs = 3.5 days/run
        # Therefore, our 90 day certs should be renewed with:
        # 90 days - 3.5 days = 86.5 days remaining,
        # which python lets us express as math by:
        # timedelta(days=90) - timedelta(days=3.5)
        # (actually it's the same as timedelta(days=86.5), but the
        #  mathy way looks cleaner and can be adjusted easier)
        REAUTHORIZE_DAYS_IN_ADVANCE = timedelta(days=90) - timedelta(
            days=GENERATE_CERTS_DAYS
        )

    # Use old configparser .get() syntax because defaults are based on values
    RSA_TAG = config.get("rsaTag", f"rsa{KEYBITS_RSA}")
    CURVE_TAG = config.get("curveTag", f"{CURVE}")

    # Endpoints taken from:
    # https://letsencrypt.org/docs/acme-protocol-updates/
    STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
    PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"

    # See for updates:
    # https://letsencrypt.org/certificates/#intermediate-certificates
    # Updates:
    #  2021-03-27: x3 expires
    #  2019-07-08: LE will provide certificates from their own root
    CROSSCHAIN_BASE = "https://letsencrypt.org/certs/"
    CROSSCHAIN_NAME_RSA = "lets-encrypt-x3-cross-signed.pem.txt"

    # TODO: turn this into a map of CHAIN = {'rsa': CHAIN_RSA, 'ec': CHAIN_EC}
    # LE plans a full ECDSA cert chain in Q3 2018
    CHAIN_RSA = "{}/{}".format(configBase, CROSSCHAIN_NAME_RSA).replace(".txt", "")

    # LE actually returns a chained cert, so we don't have to manually apply
    # the cross chain ourself, but the cross chain is useful for configuring
    # stapling.

    testing = ""
    if IS_TEST:
        testing = "[TEST MODE — DO NOT USE TEST CERTS IN PRODUCTION] "

    configuredDomains = loadDomains()

    if not IS_CRON:
        print(f"{testing}Welcome to LE Matt!")
        print("Using domain list:")
        for domain in configuredDomains:
            print(f"\t{domain}")

    if not os.path.isfile(ACCOUNT_KEY):
        print(f"Account key doesn't exist: {ACCOUNT_KEY}")
        print("Create your LE account key with: openssl genrsa 4096 > key.pem")
        sys.exit(1)

    # Fetch intermediate cert so user can copy it elsewhere if needed
    if not os.path.isfile(CHAIN_RSA):
        run(
            "wget -O{} {}{}".format(CHAIN_RSA, CROSSCHAIN_BASE, CROSSCHAIN_NAME_RSA),
            output=False,
        )

    # Create directories to store results (if they don't already exist)
    for name in ["key", "cert", "csr"]:
        gendir(getSubdir(name))

    # Parse actions.conf to load cert update actions (defaults and overrides)
    domainActions, domainActionNames = loadDomainActions()

    # Now process domains by:
    #   - requesting new certs from LE when cert doesn't exist or expires soon
    #     - generating rsa and ec keys if a key doesn't already exist
    #     - generating CSRs for each {key,domains} pair when CSRs don't exist
    #     - run per-domain prepare actions when configured
    #   - adding updated domains to results for post-update action triggering

    # We now do massively parallel certificate updating where each Certificate
    # for each domain gets processed with '--parallel' concurrency

    # LE has per-second rate limits and we don't recover from those errors
    # gracefully at the moment, so try to slow overzealous users down somewhat:
    # ==================
    # "The “new-reg”, “new-authz” and “new-cert” endpoints have an
    # Overall Requests limit of 20 per second.
    # The “/directory” endpoint and the “/acme” directory have an
    # Overall Requests limit of 40 requests per second."
    # ==================
    if concurrency > 10:
        concurrency = 10

    with multiprocessing.Pool(processes=concurrency) as pool:
        updatedCerts = pool.starmap(
            generateKeysAndCertsAndRequestSignedCerts,
            itertools.product(configuredDomains, [domainActions], ["rsa", "ec"]),
        )

    # sanity check from starmap
    assert isinstance(updatedCerts, list)
    assert len(updatedCerts) and isinstance(updatedCerts[0], dict)

    # pool.starmap() returns a list of dicts, but our final
    # result expects one dict with all results,
    # so merge the nested dicts into one big dict.
    updatedCertsSingleDict = {}
    for u in updatedCerts:
        updatedCertsSingleDict.update(u)

    # sanity check
    assert isinstance(updatedCertsSingleDict, dict)

    # Now deduplicate updated certs to action mappings then
    # copy keys, certs, and run configured update actions for updated certs
    updateKeysAndCertsAndServices(
        domainActions, domainActionNames, updatedCertsSingleDict
    )

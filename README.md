Matt's Let's Encrypt Automation
===============================

yes, let's!

## Background
### What Is It?

`lematt.py` is a self-contained certificate management system allowing you to automatically:

- provision RSA and EC keys
- generate RSA and EC CSRs
    - includes full SAN/SNI/UCC capability for up to 100 domain names per cert
- generate and renew RSA and EC LE certificates
    - including: optional pre-sign triggers per-domain in case you need to
    start up a web server or punch a hole in a firewall for validation
- copy certs and keys to multiple places when renewed
    - unlimited copy destinations can be triggered per domain name (with a default fallback)
        - copy locally
        - copy to any number of remote servers (via `rsync`)
- reload services based on the domain(s) inside renewed certs
    - unlimited update triggers can fire based on certificate domain names (with a default fallback)
        - reload local services
        - reload remote services with ssh connections
    - automatically deduplicates service update requests, so if you have 30
    web certificates update at the same time, only one reload will be executed.
- run certificate updates as a dedicated certificate-maint user
    - stop running your updates as root. you know its bad.
- continuously rotate keys and certificates as fast as every 3.5 days
    - why 3.5 days? Because LE rate limits are 5 duplicate certs per week.
        - requesting 1 RSA cert and 1 EC cert count as 2 rate limit slots, so you can run the full cycle only twice every 7 days, giving us 3.5 days between issues to stay under the rate limits.
        - whether it's wise or safe to always remain at your maximum rate limit capacity is up to you. See config option `generateNewCertsAfterDays`.
- end-to-end test your configuration, copy, pre-sign, and post-update actions using the LE staging endpoint with isolated test-specific keys, CSRs, and certs so you don't burn through production rate limits or overwrite production keys and certs with test data.

`lematt` does not change any part of your system outside of creating new keys, CSRs, and signed certificates, then running triggers up manually specify after updates. You must already have a web server where LE can discover verification challenges under the URI `/.well-known/acme-challenge/`.

### Why Is It?

Consider this a "paying off technical debt" project. My original LE automation
was a 40 line shell script looping over domains to generate RSA keys, CSRs,
certs from LE, then copying keys/certs and reloading services. The 40 line shell script
worked great for two and a half years, but now it has been upgraded to a
800+ line Python program with improved reliability, enhanced functionality, plus
general usability across different installations through better config management and
stable update triggers.

lematt can:

- generate RSA _and_ EC keys, CSRs, and request signed certs from LE
- generate SAN/SNI/UCC CSRs
	- LE allows up to 100 domain names per individual certificate
- trigger pre-LE-request actions
	-  e.g. start a web server on a remote host to accept the challenge, but just for the 3 seconds it takes to validate challenge ownership
- copy only keys and certs relevant to services on a single machine
- reload only related services when certs get renewed
- test against LE staging endpoint with dedicated test directories and test naming for keys, CSRs, and certs to protect against wiping away production keys and certs during testing


### How Is It?

Pretty good, thanks for asking.


## Usage

For a longer writeup, see [Introducing lematt](https://matt.sh/lematt)

### Running

Run lematt by giving `lematt.py` one argument of either `--test` or `--prod` along with (optional) config filename if you aren't using the default location of `conf/`.

### Configuring

lematt has three config files:

- `lematt.conf` describes global options for:
    - how many days before expiration to renew certs
    - your LE account key location
    - directory to place LE challenge verification files
    - how many bits to use for your RSA keys (default: 2048)
    - which curve to use (default: prime256v1 (also known as secp256r1))
- `domains` describes which domains to manage:
    - each line will generate a new key and new certificate
    - each line must start with a FQDN the LE server can contact
    - you can add SAN/SNI/UCC domains by just listing them on the same line separated by spaces
    - as shorthand, if you just list a subdomain without any '.', the first domain on the line will be appended to the subdomain (e.g. "mysite.com www" will make one SAN cert for "mysite.com" with altSubjectNames mysite.com,www.mysite.com)
- `actions.conf` describes commands to run before and after requesting certs:
    - section `[default]` applies to any domain without a specific override
    - overrides are any number of named sections you create (not named `[default]`)
        - overrides have a space-separated `domains` entry
        - any domain updated in the `domains` entry will trigger the override actions
            - `domains: mysite.com mail.mysite.com othersite.org`
            - Note: `domains` only makes sense in an override section. It has no effect under `[default]`.
    - actions for both `[default]` and override sections are:
        - `update` - after a certificate is updated, run these commands
            - `update: ["service nginx reload", "ssh mailserver-reload"]`
        - `prepare` - before requesting the LE cert, run these commands (useful for starting a temporary web server or opening firewall ports temporarily; command will be killed after cert is issued)
            - `prepare: ["ssh mailserver-openport http://central.validator.mysite.com"]`
        - `uploadCerts` - runs when certs are updated or created.
            - `CERTS` in your commands will be replaced with shell glob patterns
            - `uploadCerts: ["rsync -avz CERTS cert-maintainer@mailserver:/etc/ssl/"]`
        - `uploadKeys` - also runs when certs are updated or created.
            - `KEYS` in your commands will be replaced with shell glob patterns
            - `uploadKeys: ["rsync -avz KEYS cert-maintainer@mailserver:/etc/ssl/private/"]`


## More Docs

For a longer writeup, see [Introducing lematt](https://matt.sh/lematt)

### Included

`lematt` includes [acme_tiny.py](https://github.com/diafygi/acme-tiny) and relies on system-provided `openssl` to generate private keys and CSRs.

## Contribute

### Things We Could Eventually Do

Want to help? Pick a task, create an issue saying you're working on it, set a deadline for yourself, then post your progress!

- create (or find) a simple-ish python module to replace our openssl command usage (key generation, CSR generation with SANs) with [pyca/cryptography](https://cryptography.io/en/latest/)
- refactor [acme_tiny](https://github.com/diafygi/acme-tiny) to use [pyca/cryptography](https://cryptography.io/en/latest/) too (we don't care about the imaginary "stay under 200 lines, even if we have to make them _really really really_ long while removing all easy-to-read visual whitespace" limits).
- add actions.conf config ability to pick either dns-01 or http-01 challenge methods
    - will require a minimal plugin architecture to talk to DNS APIs (available from other LE clients)
    - DNS API integration would basically fire along side the current prepare hooks, but we need something other than `acme_tiny` (or a modification of it) to run the request since tiny only requests http challenges.

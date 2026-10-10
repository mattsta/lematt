"""Action pipeline contract: config-driven groups run the right commands.

actions.conf groups certificates into [default], [every] and [override-*]
sections. Prepare commands run (once per domain, kept alive) while
certificates are requested; after a run, uploadCerts/uploadKeys/update run
once per group for the certificates that were actually renewed.
"""

import os
import time

import pytest

from lematt.actions import ActionRunner
from lematt.config import CertificateResult, DomainConfig, KeyType, LemattConfig
from lematt.manager import CertificateManager

ACTIONS_CONF = """
[default]
uploadCerts: ["echo default-certs CERTS >> {log}"]
uploadKeys: ["echo default-keys KEYS >> {log}"]
update: ["echo default-update DOMAINS_CN / DOMAINS_ALL >> {log}"]

[every]
uploadCerts: ["echo every-certs CERTS >> {log}"]

[override-mail]
domains: mail.example.com
prepare: ["sh -c 'echo prepare DOMAIN >> {log}; echo $$ >> {pids}; exec sleep 30'"]
update: ["echo mail-update DOMAINS_CN >> {log}"]
"""


@pytest.fixture
def setup(tmp_path):
    log, pids = tmp_path / "actions.log", tmp_path / "prepare.pids"
    (tmp_path / "actions.conf").write_text(ACTIONS_CONF.format(log=log, pids=pids))
    config = LemattConfig(
        config_base=tmp_path,
        challenge_dir=tmp_path / "challenges",
        account_key=tmp_path / "account.key",
    )
    runner = ActionRunner(config)
    runner.load_actions()
    return config, runner, log, pids


def result(domains: list[str], *, success: bool, renewed: bool) -> CertificateResult:
    domain_config = DomainConfig(domains[0], domains[1:])
    return CertificateResult(domain_config, KeyType.RSA, success, renewed)


def test_post_renewal_actions_run_once_per_group(setup):
    config, runner, log, _ = setup
    cert, key = f"{config.config_base}/prod/cert", f"{config.config_base}/prod/key"

    runner.process_updated_certs(
        [
            result(["example.com", "www.example.com"], success=True, renewed=True),
            # Each key type is its own result; the group still runs once
            result(["example.com", "www.example.com"], success=True, renewed=True),
            result(["mail.example.com"], success=True, renewed=True),
            result(["a.example.net"], success=True, renewed=True),
            result(["skipped.example.com"], success=True, renewed=False),
            result(["failed.example.com"], success=False, renewed=True),
        ]
    )

    by_action = {
        line.split()[0]: line.split()[1:] for line in log.read_text().splitlines()
    }
    assert sorted(by_action) == [
        "default-certs",
        "default-keys",
        "default-update",
        "every-certs",
        "mail-update",
    ]
    assert by_action["default-certs"] == [
        f"{cert}/example.com*",
        f"{cert}/www.example.com*",
        f"{cert}/a.example.net*",
    ]
    assert by_action["default-keys"] == [
        f"{key}/example.com*",
        f"{key}/www.example.com*",
        f"{key}/a.example.net*",
    ]
    # DOMAINS_CN / DOMAINS_ALL: deduplicated, in the same stable order
    domains_cn, domains_all = " ".join(by_action["default-update"]).split(" / ")
    assert domains_cn.split() == ["example.com", "a.example.net"]
    assert domains_all.split() == ["example.com", "www.example.com", "a.example.net"]
    assert by_action["mail-update"] == ["mail.example.com"]
    # [every] covers all renewed certs, in addition to their own group
    assert by_action["every-certs"] == [
        f"{cert}/example.com*",
        f"{cert}/www.example.com*",
        f"{cert}/a.example.net*",
        f"{cert}/mail.example.com*",
    ]


def test_prepare_runs_once_and_stays_alive_during_issuance(setup, monkeypatch):
    config, runner, log, pids = setup
    alive_during_request: list[bool] = []

    def fake_request(self, csr, output_path, **kwargs):
        alive_during_request.append(all(map(_alive, _wait_for_pids(pids))))
        output_path.touch()
        return None  # success

    monkeypatch.setattr(CertificateManager, "request_certificate", fake_request)
    manager = CertificateManager(config)
    manager.ensure_directories()

    results = manager.process_domain_all_keys(
        DomainConfig("mail.example.com"), runner.actions
    )

    assert [(r.key_type, r.success, r.renewed) for r in results] == [
        (KeyType.RSA, True, True),
        (KeyType.EC, True, True),
    ]
    # One prepare for the cert's domain, shared by both key types
    assert log.read_text().splitlines() == ["prepare mail.example.com"]
    assert alive_during_request == [True, True]
    assert not any(map(_alive, _wait_for_pids(pids)))


def _wait_for_pids(pids, timeout: float = 5.0) -> list[int]:
    """Prepare commands start asynchronously; wait until they report in."""
    deadline = time.monotonic() + timeout
    while not (pids.exists() and pids.read_text().strip()):
        assert time.monotonic() < deadline, "prepare command never started"
        time.sleep(0.01)
    return [int(pid) for pid in pids.read_text().split()]


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True

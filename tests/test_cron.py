"""Cron mode contract: silent when nothing happens, reports when certs renew or fail."""

import re
from concurrent.futures import ProcessPoolExecutor

import pytest
from loguru import logger

from lematt.actions import ActionRunner
from lematt.cli import finish_report
from lematt.config import (
    CertificateResult,
    DomainActions,
    DomainConfig,
    KeyType,
    LemattConfig,
    RenewalSummary,
)
from lematt.executor import _worker_init
from lematt.log import setup_logging
from lematt.manager import CertificateManager, PrepareActionRunner
from lematt.renewal import RenewalDecision


def make_manager(tmp_path, **overrides) -> CertificateManager:
    config = LemattConfig(
        config_base=str(tmp_path),
        challenge_dir=str(tmp_path / "challenges"),
        account_key=str(tmp_path / "account.key"),
        **overrides,
    )
    return CertificateManager(config)


def make_summary(
    *, renewed: int = 0, failed: int = 0, skipped: int = 0
) -> RenewalSummary:
    summary = RenewalSummary(total_domains=renewed + failed + skipped)
    domain = DomainConfig("example.com")
    for _ in range(renewed):
        summary.add_result(
            CertificateResult(domain, KeyType.RSA, success=True, renewed=True)
        )
    for _ in range(failed):
        summary.add_result(
            CertificateResult(domain, KeyType.RSA, success=False, renewed=True)
        )
    for _ in range(skipped):
        summary.add_result(
            CertificateResult(domain, KeyType.RSA, success=True, renewed=False)
        )
    return summary


def test_cron_hides_routine_messages(tmp_path, capsys):
    setup_logging(cron=True)
    manager = make_manager(tmp_path, is_cron=True)

    manager.log("Not renewing!", "rsa2048")
    logger.info("▶ Starting domain: example.com (RSA + EC)")

    assert capsys.readouterr().err == ""


def test_cron_shows_renewal_events(tmp_path, capsys):
    setup_logging(cron=True)
    manager = make_manager(tmp_path, is_cron=True)

    manager.log("Renewing example.com!", "rsa2048", update=True)
    logger.success("✓ Renewed: example.com [rsa2048]")
    ActionRunner(manager.config).log(
        "[update] SUCCESS: sudo service nginx reload", "action", update=True
    )

    err = capsys.readouterr().err
    assert "Renewing example.com!" in err
    assert "✓ Renewed: example.com [rsa2048]" in err
    assert "[update] SUCCESS: sudo service nginx reload" in err


def test_cron_summary_silent_when_nothing_renewed(capsys):
    setup_logging(cron=True)

    assert finish_report(make_summary(skipped=4)) == 0
    assert capsys.readouterr().err == ""


def test_cron_summary_reported_when_renewed(capsys):
    setup_logging(cron=True)

    assert finish_report(make_summary(renewed=2, skipped=2)) == 0
    assert "Renewed: 2, Failed: 0, Skipped: 2" in capsys.readouterr().err


def test_failed_certs_report_and_exit_nonzero(capsys):
    setup_logging(cron=True)

    assert finish_report(make_summary(renewed=1, failed=1)) == 1
    assert "Renewed: 1, Failed: 1" in capsys.readouterr().err


def test_interactive_summary_always_shown(capsys):
    setup_logging()

    assert finish_report(make_summary(skipped=4)) == 0
    assert "Renewed: 0, Failed: 0, Skipped: 4" in capsys.readouterr().err


def record_prepares(monkeypatch) -> list[str]:
    prepared: list[str] = []

    def fake_prepare(self, domain, domain_actions):
        prepared.append(domain)
        return []

    monkeypatch.setattr(PrepareActionRunner, "prepare_domain", fake_prepare)
    return prepared


def test_prepare_skipped_when_nothing_due(tmp_path, monkeypatch):
    manager = make_manager(tmp_path, is_cron=True)
    prepared = record_prepares(monkeypatch)
    monkeypatch.setattr(
        "lematt.manager.decide",
        lambda *a, **k: RenewalDecision(False, "lifetime", "not due"),
    )

    results = manager.process_domain_all_keys(
        DomainConfig("mail.example.com"), DomainActions()
    )

    assert prepared == []
    assert [(r.success, r.renewed) for r in results] == [(True, False), (True, False)]


def test_prepare_runs_once_when_due(tmp_path, monkeypatch):
    manager = make_manager(tmp_path, is_dry_run=True)
    prepared = record_prepares(monkeypatch)
    monkeypatch.setattr(
        "lematt.manager.decide",
        lambda *a, **k: RenewalDecision(True, "lifetime", "due"),
    )

    manager.process_domain_all_keys(DomainConfig("mail.example.com"), DomainActions())

    assert prepared == ["mail.example.com"]


def test_worker_process_events_reach_output(tmp_path, capfd):
    """Renewals run in worker processes; their events must not be dropped."""
    manager = make_manager(tmp_path, is_cron=True)

    with ProcessPoolExecutor(
        max_workers=1, initializer=_worker_init, initargs=(manager.config,)
    ) as pool:
        pool.submit(manager.log, "Renewing example.com!", "rsa2048", True).result()

    assert "Renewing example.com!" in capfd.readouterr().err


@pytest.mark.parametrize("cron", [False, True])
def test_test_mode_tag_appears_once(tmp_path, capsys, cron):
    setup_logging(cron=cron, test_mode=True)

    make_manager(tmp_path, is_test=True).log(
        "Renewing example.com!", "rsa", update=True
    )

    line = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().err).strip()
    assert line.count("[TEST]") == 1
    assert line.endswith("> [rsa] Renewing example.com!")

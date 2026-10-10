"""End-to-end smoke tests for the read-only CLI commands."""

import json
import re
import sys

import pytest

from lematt.cli import main


@pytest.fixture
def conf(tmp_path):
    (tmp_path / "challenges").mkdir()
    (tmp_path / "lematt.conf").write_text(
        "[config]\n"
        f"challengeDropDir: {tmp_path / 'challenges'}\n"
        f"accountKey: {tmp_path / 'account.key'}\n"
        "reauthorizeDays: 30\n"
    )
    (tmp_path / "domains").write_text("example.com www mail\nb.org\n")
    (tmp_path / "actions.conf").write_text(
        '[default]\nupdate: ["true"]\n'
        "[override-b]\ndomains: b.org\n"
        'uploadCerts: ["true CERTS"]\n'
    )
    return tmp_path


def run(monkeypatch, conf, *args: str) -> int:
    monkeypatch.setattr(
        sys, "argv", ["lematt", "--test", "--config", str(conf / "lematt.conf"), *args]
    )
    return main()


def test_list_domains_json(monkeypatch, conf, capsys):
    assert run(monkeypatch, conf, "--list-domains", "--json") == 0
    assert json.loads(capsys.readouterr().out) == [
        {
            "primary": "example.com",
            "sans": ["www.example.com", "mail.example.com"],
            "all_domains": ["example.com", "www.example.com", "mail.example.com"],
        },
        {"primary": "b.org", "sans": [], "all_domains": ["b.org"]},
    ]


def test_status_json_reports_missing_certificates(monkeypatch, conf, capsys):
    assert run(monkeypatch, conf, "--status", "--json") == 0
    status = json.loads(capsys.readouterr().out)
    assert status["summary"]["total"] == 4
    assert status["summary"]["missing"] == 4


def test_validate_config(monkeypatch, conf):
    assert run(monkeypatch, conf, "--validate-config") == 0


def test_health_check_outputs(monkeypatch, conf, capsys):
    assert run(monkeypatch, conf, "--health-check", "--json") == 2
    health = json.loads(capsys.readouterr().out)
    assert health["counts"]["total"] == 4

    assert run(monkeypatch, conf, "--health-check", "--prometheus") == 2
    assert 'lematt_certificates_total{status="critical"} 4' in capsys.readouterr().out


def test_report_console(monkeypatch, conf):
    assert run(monkeypatch, conf, "--report") == 0


@pytest.mark.parametrize("suffix", [".json", ".md"])
def test_report_files(monkeypatch, conf, suffix, tmp_path_factory):
    out = tmp_path_factory.mktemp("report") / f"report{suffix}"
    assert run(monkeypatch, conf, "--report", "--report-output", str(out)) == 0
    if suffix == ".json":
        assert len(json.loads(out.read_text())["inventory"]) == 4
    else:
        assert "example.com" in out.read_text()


def test_help_topics_render(monkeypatch, conf):
    from lematt.help import HELP_TOPICS

    for topic in HELP_TOPICS:
        assert run(monkeypatch, conf, "--help-topic", topic) == 0
    assert run(monkeypatch, conf, "--help-search", "rate limit") == 0


def test_dry_run_renewal_plans_every_certificate(monkeypatch, conf, capsys):
    (conf / "account.key").write_text("placeholder")

    assert run(monkeypatch, conf, "--dry-run") == 0

    err = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().err)
    assert "Renewed: 4, Failed: 0, Skipped: 0" in err
    assert err.count("[DRY-RUN] Would request certificate") == 4
    # Post-renewal actions are planned per group with placeholders expanded
    assert f"[DRY-RUN] Would run: true {conf}/test/cert/b.org*" in err
    assert "[DRY-RUN] Would run: true\n" in err

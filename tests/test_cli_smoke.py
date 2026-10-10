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


def test_domain_filter_selects_one_certificate(monkeypatch, conf, capsys):
    assert (
        run(monkeypatch, conf, "--status", "--json", "--domain", "mail.example.com")
        == 0
    )
    status = json.loads(capsys.readouterr().out)
    assert {c["domain"] for c in status["certificates"]} == {"example.com"}

    assert run(monkeypatch, conf, "--status", "--domain", "nope.example") == 1


def test_help_and_init_toml_need_no_mode(conf):
    assert main(["--help-topic"]) == 0
    assert main(["--help-topic", "run"]) == 0
    assert main(["--help-search", "wildcard"]) == 0

    assert main(["--init-toml", "--config", str(conf / "lematt.conf")]) == 0
    assert "[config]" in (conf / "lematt.toml").read_text()


@pytest.mark.parametrize("command", [[], ["--status"], ["--print-systemd-units"]])
def test_other_commands_require_a_mode(command, capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(command)

    assert exit_info.value.code == 2
    assert "one of the arguments --prod --test is required" in capsys.readouterr().err


def test_test_notification_needs_no_challenge_directory(monkeypatch, conf):
    (conf / "challenges").rmdir()
    (conf / "lematt.toml").write_text(
        '[notifications]\ncustom_command = "true"\njournald_enabled = false\n'
    )

    assert run(monkeypatch, conf, "--test-notification") == 0

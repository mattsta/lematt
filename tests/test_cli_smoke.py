"""End-to-end smoke tests for the read-only CLI commands."""

import json
import re
import sys

import pytest

from lematt.cli import main
from lematt.config import KeyType
from lematt.crypto import generate_private_key


@pytest.fixture
def conf(tmp_path):
    (tmp_path / "challenges").mkdir()
    (tmp_path / "lematt.conf").write_text(
        "[config]\n"
        f"challengeDropDir: {tmp_path / 'challenges'}\n"
        f"accountKey: {tmp_path / 'account.key'}\n"
        "reauthorizeDays: 30\n"
    )
    (tmp_path / "domains").write_text(
        "example.com www mail\nb.org profile=shortlived\n"
    )
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
            "profile": None,
        },
        {
            "primary": "b.org",
            "sans": [],
            "all_domains": ["b.org"],
            "profile": "shortlived",
        },
    ]


def test_status_json_reports_missing_certificates(monkeypatch, conf, capsys):
    assert run(monkeypatch, conf, "--status", "--json") == 0
    summary = json.loads(capsys.readouterr().out)["summary"]
    assert summary == {
        "total": 4,
        "ok": 0,
        "renew_soon": 0,
        "critical": 0,
        "expired": 0,
        "missing": 4,
        "revoked": 0,
        "parse_error": 0,
        "unknown": 0,
    }


def test_validate_config(monkeypatch, conf):
    (conf / "account.key").write_bytes(generate_private_key(KeyType.EC))
    assert run(monkeypatch, conf, "--validate-config") == 0


@pytest.mark.parametrize(
    ("breakage", "message"),
    [
        ("no account key", "Account key doesn't exist"),
        ("bad account key", "Account key can't be used"),
        ("no challenge directory", "Challenge directory does not exist"),
    ],
)
def test_validate_config_checks_what_a_run_needs(
    monkeypatch, conf, capsys, breakage, message
):
    (conf / "account.key").write_bytes(generate_private_key(KeyType.EC))
    if breakage == "no account key":
        (conf / "account.key").unlink()
    elif breakage == "bad account key":
        (conf / "account.key").write_text("not a key")
    else:
        (conf / "challenges").rmdir()

    assert run(monkeypatch, conf, "--validate-config") == 1
    assert message in capsys.readouterr().err


def test_config_warns_about_unknown_keys_and_split_certificates(
    monkeypatch, conf, capsys
):
    with (conf / "lematt.conf").open("a") as f:
        f.write("keyBitsRsa2: 4096\n")
    (conf / "actions.conf").write_text(
        '[default]\nupdate: ["true"]\nupdateCerts: ["true"]\n'
        "[mail]\ndomains: mail.example.com b.org\n"
        "[b]\ndomains: b.org\n"
    )

    assert run(monkeypatch, conf, "--list-domains") == 0

    err = capsys.readouterr().err
    assert "ignoring unknown key 'keybitsrsa2' (did you mean 'keyBitsRSA'?)" in err
    assert "ignoring unknown key 'updatecerts' (did you mean 'uploadCerts'?)" in err
    assert "b.org is also listed in [mail]; [b] applies to it" in err
    assert (
        "certificate example.com: its names fall into action groups default, mail"
        in err
    )


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


def test_health_check_without_a_usable_config_is_unknown(tmp_path):
    missing = tmp_path / "missing" / "lematt.conf"

    assert main(["--test", "--config", str(missing), "--health-check"]) == 3
    assert main(["--test", "--config", str(missing), "--status"]) == 1


def test_help_search_finds_topics_by_their_text():
    from lematt.help import HelpSystem

    names = [topic.name for topic in HelpSystem().search("node_exporter")]
    assert "monitoring" in names  # only mentioned in the topic's text

    names = [topic.name for topic in HelpSystem().search("systemd")]
    assert names[0] == "systemd"  # name/keyword matches rank first


def test_an_empty_configuration_is_reported_not_called_healthy(
    monkeypatch, conf, capsys
):
    (conf / "domains").write_text("# only comments\n")

    assert run(monkeypatch, conf, "--report") == 0
    err = capsys.readouterr().err
    assert f"Configuration: {conf / 'lematt.conf'} (0 certificate lines" in err
    assert f"No certificates configured: {conf / 'domains'}" in err

    assert run(monkeypatch, conf, "--health-check") == 3

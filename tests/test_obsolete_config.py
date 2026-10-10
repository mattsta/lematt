"""Configs written for features Let's Encrypt removed still load, with a warning."""

from lematt.actions import ActionRunner
from lematt.cli import load_domains
from lematt.config import LemattConfig
from lematt.config_loader import ConfigLoader
from lematt.log import setup_logging


def test_ocsp_domain_flags_are_ignored_with_warning(tmp_path, capsys):
    setup_logging()
    (tmp_path / "domains").write_text("example.com www +ocsp\nother.com -ocsp\n")

    domains = load_domains(str(tmp_path))

    assert [d.all_domains for d in domains] == [
        ["example.com", "www.example.com"],
        ["other.com"],
    ]
    err = capsys.readouterr().err
    assert "domains:1: ignoring obsolete '+ocsp'" in err
    assert "domains:2: ignoring obsolete '-ocsp'" in err


def test_config_loader_ignores_ocsp_domain_flags(tmp_path):
    (tmp_path / "domains").write_text("example.com www +ocsp\n")

    domains = ConfigLoader(tmp_path).get_domains()

    assert [d.all_domains for d in domains] == [["example.com", "www.example.com"]]


def test_ocsp_action_setting_is_ignored_with_warning(tmp_path, capsys):
    setup_logging()
    (tmp_path / "actions.conf").write_text(
        "[default]\n"
        'update: ["true"]\n'
        "ocspStapleRequired: yes\n"
        "[every]\n"
        "ocspStapleRequired: no\n"
        "[override-mail]\n"
        "domains: mail.example.com\n"
        "ocspStapleRequired: yes\n"
    )
    runner = ActionRunner(
        LemattConfig(
            config_base=str(tmp_path),
            challenge_dir=str(tmp_path),
            account_key=str(tmp_path / "account.key"),
        )
    )

    runner.load_actions()

    assert runner.actions.default.update_commands == ["true"]
    assert runner.actions.get_for_domain("mail.example.com").name == "override-mail"
    err = capsys.readouterr().err
    for section in ("default", "every", "override-mail"):
        assert (
            f"actions.conf [{section}]: ignoring obsolete 'ocspStapleRequired'" in err
        )

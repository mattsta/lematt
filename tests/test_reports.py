"""--report: format selection, output destinations and the config summary."""

import json
from pathlib import Path

import pytest

from lematt.config import (
    ActionConfig,
    DomainActions,
    DomainConfig,
    KeyType,
    LemattConfig,
)
from lematt.reports import Report, generate_full_report, report_format

DOMAINS = [DomainConfig("example.com", ["www.example.com"]), DomainConfig("b.org")]


@pytest.fixture
def config(tmp_path):
    return LemattConfig(
        config_base=tmp_path / "conf",
        challenge_dir=tmp_path / "web",
        account_key=tmp_path / "conf" / "account.key",
        is_test=True,
    )


@pytest.fixture
def actions():
    return DomainActions(
        default=ActionConfig(name="default", update_commands=["true"]),
        domain_configs={
            "b.org": ActionConfig(
                name="b", domains=["b.org"], upload_certs_commands=["true"]
            )
        },
    )


@pytest.mark.parametrize(
    ("output", "requested", "expected"),
    [
        (None, None, "console"),
        (None, "json", "json"),
        (Path("r.json"), None, "json"),
        (Path("r.MD"), None, "markdown"),
        (Path("r.markdown"), None, "markdown"),
        (Path("r.txt"), None, "console"),
        (Path("r.json"), "markdown", "markdown"),  # an explicit format wins
    ],
)
def test_report_format(output, requested, expected):
    assert report_format(output, requested) == expected


def test_config_summary_reports_real_locations(config, actions):
    summary = Report(config, DOMAINS, actions).config_summary()

    assert summary["test_mode"] is True
    assert summary["cert_directory"] == str(config.config_base / "test" / "cert")
    assert summary["key_directory"] == str(config.config_base / "test" / "key")
    assert summary["challenge_directory"] == str(config.challenge_dir)
    assert summary["acme_directory"] == config.staging_url
    assert summary["domain_count"] == 2
    assert summary["san_count"] == 1
    assert summary["key_types"] == ["rsa", "ec"]
    assert summary["action_groups"] == ["default", "b"]


def test_json_without_output_file_goes_to_stdout(config, actions, capsys):
    generate_full_report(config, DOMAINS, actions, format="json")

    data = json.loads(capsys.readouterr().out)
    assert data["config"]["cert_directory"] == str(config.mode_dir("cert"))
    assert {item["domain"] for item in data["inventory"]} == {"example.com", "b.org"}
    assert len(data["inventory"]) == 4  # RSA + EC per certificate line


@pytest.mark.parametrize(
    ("name", "requested", "marker"),
    [
        ("report.md", None, "- Certificate directory: `"),
        ("report.txt", None, "Certificate directory: "),  # console text
        ("report.txt", "json", '"inventory"'),
    ],
)
def test_output_file_is_always_written(
    config, actions, tmp_path, name, requested, marker
):
    output = tmp_path / "out" / name

    generate_full_report(config, DOMAINS, actions, output_path=output, format=requested)

    text = output.read_text()
    assert marker in text
    assert "N/A" not in text
    assert "\x1b[" not in text


def test_markdown_lists_paths_and_actions(config, actions):
    text = Report(config, DOMAINS, actions).to_markdown()

    assert f"- Certificate directory: `{config.mode_dir('cert')}`" in text
    assert f"`{config.get_cert_path(DOMAINS[0], KeyType.RSA)}`" in text
    assert "## Deployment Actions" in text
    assert "| default | unlisted names | 0 | 0 | 0 | 1 |" in text
    assert "| b | b.org | 0 | 1 | 0 | 0 |" in text

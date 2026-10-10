"""Configuration loading: INI and TOML layouts, and operator-facing errors."""

import json
import sys

import pytest

from lematt.cli import main
from lematt.config_loader import ConfigError, ConfigLoader

INI = """[config]
challengeDropDir: {base}/challenges
accountKey: {base}/account.key
reauthorizeDays: 21.5
keyBitsRSA: 3072
curve: secp384r1
"""

TOML = """[config]
challenge_dir = "{base}/challenges"
account_key = "{base}/account.key"
reauthorize_days = 21.5
key_bits_rsa = 3072
ec_curve = "secp384r1"

[[domains]]
primary = "example.com"
sans = ["www", "mail.example.org"]

[actions.default]
update = ["systemctl reload nginx"]

[actions.every]
upload_certs = ["rsync CERTS backup:"]

[actions.mail]
domains = ["mail.example.org"]
prepare = ["ssh mail-forward"]
"""


def write(base, name: str, content: str):
    path = base / name
    path.write_text(content.format(base=base))
    return path


def cli(monkeypatch, config, *args: str) -> int:
    monkeypatch.setattr(
        sys, "argv", ["lematt", "--test", "--config", str(config), *args]
    )
    return main()


@pytest.fixture
def ini_dir(tmp_path):
    (tmp_path / "challenges").mkdir()
    write(tmp_path, "lematt.conf", INI)
    write(tmp_path, "domains", "example.com www mail.example.org\n")
    write(
        tmp_path,
        "actions.conf",
        '[default]\nupdate: ["systemctl reload nginx"]\n'
        '[every]\nuploadCerts: ["rsync CERTS backup:"]\n'
        '[mail]\ndomains: mail.example.org\nprepare: ["ssh mail-forward"]\n',
    )
    return tmp_path


def load(path) -> ConfigLoader:
    loader = ConfigLoader(path.parent, config_file=path)
    loader.load()
    return loader


def summarize(loader: ConfigLoader):
    config = loader.get_lematt_config(is_test=True)
    actions = loader.get_actions()
    return (
        (config.reauthorize_days, config.rsa_key_bits, config.ec_curve, config.rsa_tag),
        [d.all_domains for d in loader.get_domains()],
        actions.default.update_commands,
        actions.every.upload_certs_commands if actions.every else None,
        actions.get_for_domain("mail.example.org").prepare_commands,
    )


EXPECTED = (
    (21.5, 3072, "secp384r1", "rsa3072"),
    [["example.com", "www.example.com", "mail.example.org"]],
    ["systemctl reload nginx"],
    ["rsync CERTS backup:"],
    ["ssh mail-forward"],
)


def test_ini_and_toml_layouts_load_identically(ini_dir, tmp_path_factory):
    toml_dir = tmp_path_factory.mktemp("toml")
    (toml_dir / "challenges").mkdir()

    ini = load(ini_dir / "lematt.conf")
    toml = load(write(toml_dir, "lematt.toml", TOML))

    assert summarize(ini) == summarize(toml) == EXPECTED
    assert ini.validate() == ([], [])
    assert toml.validate() == ([], [])


def test_cli_accepts_toml_config(monkeypatch, tmp_path, capsys):
    (tmp_path / "challenges").mkdir()
    config = write(tmp_path, "lematt.toml", TOML)

    assert cli(monkeypatch, config, "--list-domains", "--json") == 0
    assert json.loads(capsys.readouterr().out)[0]["sans"] == [
        "www.example.com",
        "mail.example.org",
    ]
    assert cli(monkeypatch, config, "--validate-config") == 0


def test_toml_without_inline_tables_uses_domains_and_actions_files(ini_dir):
    config = write(
        ini_dir, "lematt.toml", '[config]\naccount_key = "k"\nchallenge_dir = "c"\n'
    )
    assert [d.primary_domain for d in load(config).get_domains()] == ["example.com"]
    assert load(config).get_actions().default.update_commands == [
        "systemctl reload nginx"
    ]


def test_stray_lematt_toml_does_not_replace_ini_config(monkeypatch, ini_dir, capsys):
    write(ini_dir, "lematt.toml", TOML.replace("example.com", "wrong.example"))

    assert cli(monkeypatch, ini_dir / "lematt.conf", "--list-domains", "--json") == 0
    assert json.loads(capsys.readouterr().out)[0]["primary"] == "example.com"


@pytest.mark.parametrize(
    ("file", "content", "message"),
    [
        ("lematt.conf", INI.replace("21.5", "soon"), "invalid reauthorizeDays value"),
        ("lematt.conf", "[other]\n", "missing [config] section"),
        (
            "actions.conf",
            "[mail]\nupdate: []\n",
            "actions.conf [mail]: missing 'domains'",
        ),
        (
            "actions.conf",
            "[default]\ndomains: a.com\n",
            "actions.conf [default]: 'domains' is not allowed",
        ),
        (
            "actions.conf",
            "[default]\nupdate: systemctl reload nginx\n",
            "'update' must be a JSON list of commands",
        ),
        ("domains", "a.com " + " ".join(f"s{i}" for i in range(100)), "at most 100"),
    ],
)
def test_invalid_ini_config_fails_with_explanation(
    monkeypatch, ini_dir, capsys, file, content, message
):
    write(ini_dir, file, content)

    assert cli(monkeypatch, ini_dir / "lematt.conf", "--validate-config") == 1
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    ("replace", "message"),
    [
        (
            ("key_bits_rsa = 3072", 'key_bits_rsa = "3072"'),
            "key_bits_rsa must be an integer",
        ),
        (("reauthorize_days = 21.5", "reauthorize_days = true"), "must be a number"),
        (('primary = "example.com"', 'name = "example.com"'), "missing 'primary'"),
        (('domains = ["mail.example.org"]', ""), "[actions.mail]: missing 'domains'"),
    ],
)
def test_invalid_toml_config_fails_with_explanation(tmp_path, replace, message):
    config = write(tmp_path, "lematt.toml", TOML.replace(*replace))

    with pytest.raises(ConfigError, match=message.replace("[", r"\[")):
        loader = load(config)
        loader.get_domains()
        loader.get_actions()


def test_curves_lets_encrypt_rejects_are_flagged(ini_dir):
    write(ini_dir, "lematt.conf", INI.replace("secp384r1", "secp521r1"))

    _, warnings = load(ini_dir / "lematt.conf").validate()

    assert any("not accepted by Let's Encrypt" in w for w in warnings)


def test_profiles_from_domains_file_and_defaults(ini_dir):
    write(ini_dir, "lematt.conf", INI + "profile: tlsserver\n")
    write(ini_dir, "domains", "example.com www\nfast.example.com profile=shortlived\n")

    loader = load(ini_dir / "lematt.conf")
    config = loader.get_lematt_config()
    domains = loader.get_domains()

    assert [config.profile_for(d) for d in domains] == ["tlsserver", "shortlived"]
    assert domains[1].all_domains == ["fast.example.com"]


def test_toml_profiles(tmp_path):
    config = write(
        tmp_path,
        "lematt.toml",
        TOML.replace(
            'sans = ["www", "mail.example.org"]',
            'sans = ["www"]\nprofile = "shortlived"',
        ),
    )

    assert load(config).get_domains()[0].profile == "shortlived"


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("a.com colour=blue", "unknown option 'colour'"),
        ("a.com profile=", "invalid profile"),
    ],
)
def test_bad_domain_options_are_rejected(ini_dir, line, message):
    write(ini_dir, "domains", line + "\n")

    with pytest.raises(ConfigError, match=message):
        load(ini_dir / "lematt.conf").get_domains()

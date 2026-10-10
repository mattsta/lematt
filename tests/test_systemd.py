"""systemd units: runnable commands, install/uninstall, printing."""

import sys

from lematt.cli import main
from lematt.systemd import (
    PRESETS,
    SystemdConfig,
    SystemdInstaller,
    generate_service_unit,
)


def test_service_runs_lematt_with_an_explicit_mode_quietly():
    prod = generate_service_unit(SystemdConfig(config_file="/etc/lematt/lematt.conf"))
    test = generate_service_unit(SystemdConfig(use_test_mode=True))

    assert (
        f"ExecStart={sys.executable} -m lematt --config /etc/lematt/lematt.conf --prod --cron"
        in prod
    )
    assert "--test --cron" in test
    assert "WorkingDirectory=/etc/lematt" in prod
    assert "SuccessExitStatus=75" in prod  # overlapping run is not a failure
    assert "TimeoutStartSec=" in prod
    # Actions need ~/.ssh, arbitrary upload paths and sudo: no sandboxing
    for directive in (
        "ProtectSystem",
        "ProtectHome",
        "NoNewPrivileges",
        "lematt-notify",
    ):
        assert directive not in prod


def test_presets_all_check_at_least_daily():
    assert set(PRESETS) == {"default", "aggressive", "conservative"}


def test_install_and_uninstall(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        SystemdInstaller, "_systemctl", lambda self, *a, check=True: calls.append(a)
    )
    installer = SystemdInstaller(SystemdConfig(), systemd_dir=tmp_path)

    assert installer.install()
    assert installer.service_path.read_text().startswith("[Unit]")
    assert installer.timer_path.exists()
    assert ("enable", "--now", "lematt-renew.timer") in calls

    assert installer.uninstall()
    assert list(tmp_path.iterdir()) == []


def test_print_units_command(monkeypatch, capsys, tmp_path):
    config = tmp_path / "lematt.conf"
    monkeypatch.setattr(
        sys,
        "argv",
        ["lematt", "--prod", "--config", str(config), "--print-systemd-units"],
    )

    assert main() == 0

    out = capsys.readouterr().out
    assert "# /etc/systemd/system/lematt-renew.service" in out
    assert f"--config {config} --prod --cron" in out
    assert "OnCalendar=*-*-* 00,12:00:00" in out

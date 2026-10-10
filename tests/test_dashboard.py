"""Headless smoke test for the --dashboard TUI."""

import asyncio

import pytest
from textual.widgets import DataTable

from lematt.config import DomainConfig, LemattConfig
from lematt.health import HealthChecker
from lematt.tui.app import DashboardConfig, LemattDashboardApp
from lematt.tui.screens import CertificateDetailScreen
from lematt.tui.widgets import CertificateTable


@pytest.mark.asyncio
async def test_dashboard_loads_switches_views_and_quits(tmp_path):
    config = LemattConfig(
        config_base=str(tmp_path),
        challenge_dir=str(tmp_path),
        account_key=str(tmp_path / "account.key"),
    )
    domains = [DomainConfig("example.com", ["www.example.com"]), DomainConfig("b.org")]
    app = LemattDashboardApp(
        health_checker=HealthChecker(config=config),
        domains=domains,
        config=DashboardConfig(auto_refresh=False),
    )

    async with app.run_test() as pilot:
        for _ in range(100):
            if app.health_data is not None:
                break
            await asyncio.sleep(0.05)
        await pilot.pause()

        # RSA + EC for each configured certificate (all missing on disk)
        assert app.health_data is not None
        table = app.screen.query_one(CertificateTable)
        assert len(table.certificates) == 4
        rows = table.query_one("#cert-table", DataTable)
        assert str(rows.get_row_at(0)[0]) == "✗ critical"  # missing file

        for key in ("2", "3", "4", "1", "p", "p", "r"):
            await pilot.press(key)
        await pilot.pause()

        app.push_screen(CertificateDetailScreen(table.certificates[0]))
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()

        await pilot.press("q")
    assert app.return_code in (0, None)

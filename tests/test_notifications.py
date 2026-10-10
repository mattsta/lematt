"""Notifications from renewal runs and their configuration."""

from lematt.notifications import NotificationConfig, run_notifications


def test_run_history_becomes_one_event_per_kind():
    history = [
        {"event": "issued", "cert": "a.rsa2048", "not_after": "2027-01-01T00:00:00Z"},
        {
            "event": "issued",
            "cert": "a.prime256v1",
            "not_after": "2027-01-01T00:00:00Z",
        },
        {
            "event": "renewal_failed",
            "cert": "b.rsa2048",
            "error": "rateLimited: slow",
            "next_attempt_after": "2026-10-11T00:00:00Z",
        },
        {
            "event": "renewal_window",
            "cert": "c.rsa2048",
            "explanation_url": "https://ca/x",
        },
        {"event": "renewal_window", "cert": "d.rsa2048", "explanation_url": None},
        {"event": "account_registered"},
    ]

    events = {e.event_type: e for e in run_notifications(history)}

    assert set(events) == {"failure", "warning", "success"}
    assert events["failure"].details == {
        "b.rsa2048": "rateLimited: slow (next attempt after 2026-10-11T00:00:00Z)"
    }
    assert events["warning"].details == {"c.rsa2048": "https://ca/x"}
    assert events["success"].message == "Renewed 2 certificate(s)"


def test_quiet_runs_send_nothing():
    assert (
        run_notifications([{"event": "renewal_window", "explanation_url": None}]) == []
    )


def test_settings_honor_all_known_keys_and_warn_about_others(capsys):
    from lematt.log import setup_logging

    setup_logging()
    config = NotificationConfig.from_settings(
        {"custom_command": "/bin/true", "notify_on_success": True, "colour": "red"}
    )

    assert config.notify_on_success is True
    assert config.create_manager().notify_on_success is True
    assert "ignoring unknown key 'colour'" in capsys.readouterr().err

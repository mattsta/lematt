"""Notifications from renewal runs and their configuration."""

from dataclasses import dataclass, field

from lematt.notifications import (
    CommandBackend,
    NotificationBackend,
    NotificationConfig,
    NotificationEvent,
    NotificationManager,
    PagerDutyBackend,
    run_notifications,
)


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


def test_revocations_are_reported():
    (event,) = run_notifications(
        [
            {
                "event": "revoked",
                "cert": "a.rsa2048",
                "serial": "0a",
                "reason": "keyCompromise",
            }
        ]
    )

    assert (event.event_type, event.title) == ("warning", "Certificates Revoked")
    assert event.details == {"a.rsa2048": "serial 0a (keyCompromise)"}


@dataclass
class RecordingBackend(NotificationBackend):
    sent: list[NotificationEvent] = field(default_factory=list)

    @property
    def name(self) -> str:
        return "recording"

    def send(self, event: NotificationEvent) -> bool:
        self.sent.append(event)
        return True


def test_backends_that_skip_an_event_are_not_reported_as_sent():
    recorder = RecordingBackend()
    manager = NotificationManager()
    manager.add_backend(PagerDutyBackend(routing_key="key"))  # failures only
    manager.add_backend(recorder)
    event = NotificationEvent(event_type="info", title="Test", message="hello")

    assert manager.notify(event) == {"recording": True}
    assert recorder.sent == [event]
    assert PagerDutyBackend(routing_key="key", only_on_failure=False).accepts(event)


def test_custom_command_may_include_arguments(tmp_path):
    script = tmp_path / "notify.sh"
    out = tmp_path / "args.txt"
    script.write_text(f'printf "%s\\n" "$@" > "{out}"\n')
    event = NotificationEvent(event_type="failure", title="Renewal failed", message="x")

    assert CommandBackend(f"sh {script} --channel 'ops alerts'").send(event)

    assert out.read_text().splitlines()[:5] == [
        "--channel",
        "ops alerts",
        "failure",
        "Renewal failed",
        "x",
    ]

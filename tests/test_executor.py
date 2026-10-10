"""Executor: sequential/parallel runs, progress tracking, prepare locks."""

import threading

import pytest

import lematt.executor
from lematt.config import DomainActions, DomainConfig, KeyType, LemattConfig
from lematt.executor import CertificateExecutor, TaskStatus
from lematt.manager import PrepareActionRunner


@pytest.fixture
def config(tmp_path):
    return LemattConfig(
        config_base=str(tmp_path),
        challenge_dir=str(tmp_path),
        account_key=str(tmp_path / "account.key"),
        is_dry_run=True,
    )


DOMAINS = [
    DomainConfig("example.com", ["www.example.com"]),
    DomainConfig("example.org"),
    DomainConfig("shared.example.net", ["www.example.com"]),  # shares a name
]


@pytest.mark.parametrize("workers", [1, 2])
def test_batch_records_every_certificate(config, workers):
    executor = CertificateExecutor(config, max_workers=workers)

    summary = executor.process_batch(DOMAINS, DomainActions())

    assert sorted((r.domain, r.key_type.name) for r in summary.results) == sorted(
        (d.primary_domain, kt.name) for d in DOMAINS for kt in KeyType
    )
    assert summary.renewed_count == 6  # dry-run "renews" missing certificates
    progress = executor.progress
    assert (progress.total, progress.completed, progress.succeeded) == (6, 6, 6)
    assert all(t.status == TaskStatus.SUCCESS for t in progress.tasks.values())


def test_worker_crash_is_isolated_to_its_certificate(config, monkeypatch):
    from lematt.manager import CertificateManager

    original = CertificateManager.process_domain_all_keys

    def explode_for_org(self, domain_config, domain_actions):
        if domain_config.primary_domain == "example.org":
            raise RuntimeError("boom")
        return original(self, domain_config, domain_actions)

    monkeypatch.setattr(CertificateManager, "process_domain_all_keys", explode_for_org)

    summary = CertificateExecutor(config, max_workers=1).process_batch(
        DOMAINS, DomainActions()
    )

    failed = {(r.domain, r.success) for r in summary.results if not r.success}
    assert failed == {("example.org", False)}
    assert summary.failed_count == 2 and summary.renewed_count == 4


def test_prepare_locks_are_sorted_and_always_released(config, monkeypatch):
    acquired: list[str] = []

    class RecordingLock:
        def __init__(self, name):
            self.name, self.lock = name, threading.Lock()

        def acquire(self):
            acquired.append(self.name)
            self.lock.acquire()

        def release(self):
            self.lock.release()

    locks = {n: RecordingLock(n) for n in ("b.example", "a.example", "c.example")}
    monkeypatch.setattr(lematt.executor, "_domain_locks", locks)
    runner = PrepareActionRunner(config)

    runner.lock_domains(["c.example", "a.example", "b.example", "a.example"])
    runner.cleanup([])  # no prepare processes were started

    assert acquired == ["a.example", "b.example", "c.example"]
    assert not any(lock.lock.locked() for lock in locks.values())


def test_sequential_runs_need_no_locks(config):
    runner = PrepareActionRunner(config)

    runner.lock_domains(["example.com"])

    assert runner._held_locks == []


def test_parallel_workers_receive_prepare_locks(config, capfd):
    config.verbose = True  # workers log lock activity at debug level

    CertificateExecutor(config, max_workers=2).process_batch(DOMAINS, DomainActions())

    err = capfd.readouterr().err
    assert "Acquiring lock for domain: www.example.com" in err
    assert "Released lock for domain: www.example.com" in err


def test_terminated_workers_unwind_for_cleanup():
    import signal

    with pytest.raises(SystemExit) as exited:
        lematt.executor._exit_on_sigterm(signal.SIGTERM, None)
    assert exited.value.code == 143


def test_second_signal_terminates_running_workers(config):
    terminated = []

    class Pool:
        def terminate_workers(self):
            terminated.append(True)

    executor = CertificateExecutor(config, max_workers=2)
    executor._pool = Pool()
    executor._signal_handler(2, None)  # first: graceful
    assert terminated == []
    with pytest.raises(KeyboardInterrupt):
        executor._signal_handler(2, None)
    assert terminated == [True]

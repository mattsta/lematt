"""Concurrent certificate processing with error isolation and clean shutdown.

Each configured certificate (a domains-file line) is one unit of work:
its RSA and EC certificates are processed together so prepare actions run
once per domain. Work runs sequentially or in a process pool; either way
results are recorded the same way and progress is logged as it changes.
"""

import multiprocessing
import signal
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from loguru import logger

from lematt.config import (
    CertificateResult,
    DomainActions,
    DomainConfig,
    KeyType,
    LemattConfig,
    RenewalSummary,
)
from lematt.log import setup_logging

KEY_TYPES = (KeyType.RSA, KeyType.EC)
MAX_WORKERS = 10

# Per-domain locks that serialize prepare actions across worker processes
# (e.g. two certificates sharing a name and its challenge forwarder).
# Set in workers by _worker_init; None in the parent and in sequential runs.
_domain_locks: dict[str, Any] | None = None


def _get_domain_lock(domain: str) -> Any:
    """The cross-process lock for ``domain``.

    Raises:
        RuntimeError: Not running in a parallel worker (no locking needed).
    """
    if _domain_locks is None or domain not in _domain_locks:
        raise RuntimeError("Domain locks not initialized")
    return _domain_locks[domain]


def _exit_on_sigterm(signum: int, frame: object) -> None:
    """Unwind a terminated worker so `finally` blocks kill prepare processes."""
    raise SystemExit(128 + signum)


def _worker_init(
    config: LemattConfig, domain_locks: dict[str, Any] | None = None
) -> None:
    """Initialize a worker: logging like the parent, locks, ignore SIGINT.

    Workers start fresh (forkserver/spawn) with no log handlers and no
    inherited globals, so both are handed over explicitly. SIGINT is
    ignored because the parent coordinates shutdown.
    """
    global _domain_locks
    _domain_locks = domain_locks
    setup_logging(verbose=config.verbose, cron=config.is_cron, test_mode=config.is_test)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, _exit_on_sigterm)


def _process_domain_worker(
    domain_config: DomainConfig,
    config: LemattConfig,
    domain_actions: DomainActions,
) -> list[CertificateResult]:
    """Process one certificate (all key types) in a worker process."""
    from lematt.manager import CertificateManager

    return CertificateManager(config).process_domain_all_keys(
        domain_config, domain_actions
    )


def task_key(domain_config: DomainConfig, key_type: KeyType) -> str:
    return f"{domain_config.primary_domain}[{key_type}]"


class TaskStatus(Enum):
    """Status of a certificate processing task."""

    PENDING = auto()
    RUNNING = auto()
    SUCCESS = auto()
    FAILED = auto()
    CANCELLED = auto()


FINISHED = (TaskStatus.SUCCESS, TaskStatus.FAILED, TaskStatus.CANCELLED)


@dataclass
class TaskProgress:
    """Progress information for a single task."""

    domain: str
    key_type: KeyType
    status: TaskStatus = TaskStatus.PENDING
    message: str = ""


@dataclass
class BatchProgress:
    """Progress information for a batch of certificate operations."""

    total: int = 0
    completed: int = 0
    succeeded: int = 0
    failed: int = 0
    cancelled: int = 0
    tasks: dict[str, TaskProgress] = field(default_factory=dict)

    @property
    def pending(self) -> int:
        return self.total - self.completed

    @property
    def percent_complete(self) -> float:
        if self.total == 0:
            return 100.0
        return (self.completed / self.total) * 100

    def update(self, key: str, status: TaskStatus, message: str = "") -> None:
        """Update a task; counters change only on the first finishing update."""
        task = self.tasks.get(key)
        if task is None:
            return
        was_finished = task.status in FINISHED
        task.status, task.message = status, message
        if was_finished or status not in FINISHED:
            return
        self.completed += 1
        if status == TaskStatus.SUCCESS:
            self.succeeded += 1
        elif status == TaskStatus.FAILED:
            self.failed += 1
        else:
            self.cancelled += 1


@dataclass
class CertificateExecutor:
    """Runs certificate work sequentially or in parallel.

    Features:
    - Error isolation: one certificate's failure doesn't affect others
    - Progress tracking: per-task status, logged as it changes
    - Graceful shutdown: first SIGINT/SIGTERM finishes in-flight work and
      skips the rest; a second one terminates running workers (after their
      prepare processes are stopped)
    """

    config: LemattConfig
    max_workers: int | None = None
    progress_callback: Callable[[BatchProgress], None] | None = None

    progress: BatchProgress = field(default_factory=BatchProgress)
    summary: RenewalSummary = field(default_factory=RenewalSummary)
    _shutdown_event: threading.Event = field(
        default_factory=threading.Event, repr=False
    )
    _signal_count: int = field(default=0, repr=False)
    _original_handlers: dict[int, Any] = field(default_factory=dict, repr=False)
    _pool: ProcessPoolExecutor | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        workers = (
            self.config.concurrency if self.max_workers is None else self.max_workers
        )
        self.max_workers = max(1, min(workers, MAX_WORKERS))

    # -- signals ------------------------------------------------------------

    def _setup_signal_handlers(self) -> None:
        for signum in (signal.SIGINT, signal.SIGTERM):
            self._original_handlers[signum] = signal.signal(
                signum, self._signal_handler
            )

    def _restore_signal_handlers(self) -> None:
        for signum, handler in self._original_handlers.items():
            signal.signal(signum, handler)
        self._original_handlers.clear()

    def _signal_handler(self, signum: int, frame: object) -> None:
        self._signal_count += 1
        if self._signal_count == 1:
            logger.warning(
                f"Received signal {signum} - graceful shutdown initiated. "
                "Press Ctrl-C again to force immediate exit."
            )
            self._shutdown_event.set()
            return

        logger.error(
            f"Received signal {signum} again ({self._signal_count} times) - "
            "forcing immediate exit!"
        )
        if self._pool is not None:
            logger.warning("Forcefully terminating worker processes...")
            # Stop running workers too; they turn SIGTERM into SystemExit so
            # their cleanup (killing prepare processes) still runs
            self._pool.terminate_workers()
        self._restore_signal_handlers()
        raise KeyboardInterrupt("Forced shutdown by user")

    # -- progress -----------------------------------------------------------

    def _mark(
        self, domain_config: DomainConfig, status: TaskStatus, message: str = ""
    ) -> None:
        for key_type in KEY_TYPES:
            self.progress.update(task_key(domain_config, key_type), status, message)

    def _record(self, results: Iterable[CertificateResult]) -> None:
        """Add results to the summary, update progress, and log each one."""
        for result in results:
            self.summary.add_result(result)
            label = f"{result.domain} [{result.key_type}]"
            key = task_key(result.domain_config, result.key_type)
            if result.success:
                self.progress.update(key, TaskStatus.SUCCESS)
                if result.renewed:
                    logger.success(f"✓ Renewed: {label}")
                else:
                    logger.info(f"✓ Valid: {label} (skipped)")
            else:
                error = result.error_message or "Unknown error"
                self.progress.update(key, TaskStatus.FAILED, error)
                logger.error(f"✗ Failed: {label} - {error}")
        self._log_progress()

    def _record_failure(self, domain_config: DomainConfig, error: str) -> None:
        self._record(
            CertificateResult(
                domain_config, kt, success=False, renewed=True, error_message=error
            )
            for kt in KEY_TYPES
        )

    def _log_progress(self) -> None:
        p = self.progress
        by_status: dict[TaskStatus, list[str]] = {}
        for key, task in p.tasks.items():
            by_status.setdefault(task.status, []).append(key)

        logger.info(
            f"Progress: {p.completed}/{p.total} ({p.percent_complete:.1f}%) - "
            f"Success: {p.succeeded}, Failed: {p.failed}, "
            f"In-Progress: {len(by_status.get(TaskStatus.RUNNING, []))}, "
            f"Pending: {len(by_status.get(TaskStatus.PENDING, []))}"
        )
        for status, icon, log in (
            (TaskStatus.SUCCESS, "✓ Successful", logger.info),
            (TaskStatus.FAILED, "✗ Failed", logger.warning),
            (TaskStatus.RUNNING, "▶ In-Progress", logger.info),
            (TaskStatus.PENDING, "⏳ Pending", logger.info),
        ):
            if keys := by_status.get(status):
                log(f"  {icon}: {', '.join(keys)}")

        if self.progress_callback:
            self.progress_callback(p)

    # -- execution ----------------------------------------------------------

    def process_batch(
        self,
        domains: list[DomainConfig],
        domain_actions: DomainActions,
    ) -> RenewalSummary:
        """Process every configured certificate (RSA and EC) and summarize."""
        self.summary = RenewalSummary()
        self.progress = BatchProgress(total=len(domains) * len(KEY_TYPES))
        for domain_config in domains:
            for key_type in KEY_TYPES:
                self.progress.tasks[task_key(domain_config, key_type)] = TaskProgress(
                    domain=domain_config.primary_domain, key_type=key_type
                )

        self._setup_signal_handlers()
        try:
            if self.max_workers == 1:
                self._process_sequential(domains, domain_actions)
            else:
                self._process_parallel(domains, domain_actions)
        finally:
            self._restore_signal_handlers()
        return self.summary

    def _process_sequential(
        self, domains: list[DomainConfig], domain_actions: DomainActions
    ) -> None:
        from lematt.manager import CertificateManager

        manager = CertificateManager(self.config)
        for domain_config in domains:
            if self._shutdown_event.is_set():
                logger.info(
                    f"Skipping {domain_config.primary_domain} due to shutdown request"
                )
                self._mark(domain_config, TaskStatus.CANCELLED)
                continue

            logger.info(f"▶ Starting domain: {domain_config.primary_domain} (RSA + EC)")
            self._mark(domain_config, TaskStatus.RUNNING)
            self._log_progress()
            try:
                self._record(
                    manager.process_domain_all_keys(domain_config, domain_actions)
                )
            except KeyboardInterrupt:
                logger.warning(
                    f"Interrupted during {domain_config.primary_domain}, stopping immediately"
                )
                self._shutdown_event.set()
                self._mark(domain_config, TaskStatus.CANCELLED, "Interrupted by user")
                raise
            except Exception as e:
                logger.exception(f"Error processing {domain_config.primary_domain}")
                self._record_failure(domain_config, f"Executor error: {e}")

    def _process_parallel(
        self, domains: list[DomainConfig], domain_actions: DomainActions
    ) -> None:
        names = sorted({name for d in domains for name in d.all_domains})
        lock_manager = multiprocessing.Manager()
        try:
            locks = {name: lock_manager.Lock() for name in names}
            with ProcessPoolExecutor(
                max_workers=self.max_workers,
                initializer=_worker_init,
                initargs=(self.config, locks),
            ) as pool:
                self._pool = pool
                futures: dict[Future[list[CertificateResult]], DomainConfig] = {}
                for domain_config in domains:
                    if self._shutdown_event.is_set():
                        self._mark(domain_config, TaskStatus.CANCELLED)
                        continue
                    logger.info(
                        f"▶ Starting: {domain_config.primary_domain} (RSA + EC)"
                    )
                    self._mark(domain_config, TaskStatus.RUNNING)
                    future = pool.submit(
                        _process_domain_worker,
                        domain_config,
                        self.config,
                        domain_actions,
                    )
                    futures[future] = domain_config
                self._collect(futures)
        finally:
            self._pool = None
            lock_manager.shutdown()

    def _collect(
        self, futures: dict[Future[list[CertificateResult]], DomainConfig]
    ) -> None:
        """Record results as workers finish; log progress while waiting."""
        pending = set(futures)
        last_activity = time.monotonic()
        while pending:
            if self._shutdown_event.is_set():
                for future in pending:
                    if future.cancel():
                        self._mark(futures[future], TaskStatus.CANCELLED)
            done, pending = wait(pending, timeout=1.0, return_when=FIRST_COMPLETED)
            for future in done:
                domain_config = futures[future]
                if future.cancelled():
                    continue
                try:
                    self._record(future.result())
                except Exception as e:
                    logger.error(
                        f"Error processing domain {domain_config.primary_domain}: {e}"
                    )
                    self._record_failure(domain_config, f"Executor error: {e}")
            if done:
                last_activity = time.monotonic()
            elif time.monotonic() - last_activity >= 10.0:
                logger.info("⏳ Still processing certificates...")
                self._log_progress()
                last_activity = time.monotonic()


def create_progress_printer(verbose: bool = False) -> Callable[[BatchProgress], None]:
    """Create a progress callback that logs running tasks in verbose mode."""

    def printer(progress: BatchProgress) -> None:
        if verbose:
            for key, task in progress.tasks.items():
                if task.status == TaskStatus.RUNNING:
                    logger.debug(f"  [{key}] {task.status.name}")

    return printer

"""Concurrent certificate processing with reliability guarantees.

This module provides a robust executor for parallel certificate operations
with proper error isolation, rate limiting, progress tracking, and graceful
shutdown handling.
"""

import multiprocessing
import signal
import threading
import time
from concurrent.futures import Future, ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

from loguru import logger

from lematt.config import (
    CertificateResult,
    DomainActions,
    DomainConfig,
    KeyType,
    LemattConfig,
    RenewalSummary,
    WorkerResult,
)

if TYPE_CHECKING:
    from collections.abc import Callable

# Global lock manager for domain-level prepare action serialization
# This ensures only one prepare action runs per domain at a time,
# preventing port conflicts when parallel processing multiple key types
_lock_manager: multiprocessing.managers.SyncManager | None = None
_domain_locks: multiprocessing.managers.DictProxy | None = None  # type: ignore[type-arg]


def _init_domain_locks() -> None:
    """Initialize the global domain lock manager for parallel processing."""
    global _lock_manager, _domain_locks
    if _lock_manager is None:
        _lock_manager = multiprocessing.Manager()
        _domain_locks = _lock_manager.dict()


def _shutdown_domain_locks() -> None:
    """Shutdown the domain lock manager."""
    global _lock_manager, _domain_locks
    if _lock_manager is not None:
        _lock_manager.shutdown()
        _lock_manager = None
        _domain_locks = None


def _get_domain_lock(domain: str) -> multiprocessing.synchronize.Lock:
    """Get or create a lock for a specific domain.

    Args:
        domain: Domain name to get lock for.

    Returns:
        Lock for the domain.
    """
    global _domain_locks, _lock_manager
    if _domain_locks is None or _lock_manager is None:
        raise RuntimeError("Domain locks not initialized")

    if domain not in _domain_locks:
        _domain_locks[domain] = _lock_manager.Lock()

    return _domain_locks[domain]  # type: ignore[return-value,no-any-return]


class TaskStatus(Enum):
    """Status of a certificate processing task."""

    PENDING = auto()
    RUNNING = auto()
    SUCCESS = auto()
    FAILED = auto()
    CANCELLED = auto()


@dataclass
class TaskProgress:
    """Progress information for a single task."""

    domain: str
    key_type: KeyType
    status: TaskStatus = TaskStatus.PENDING
    message: str = ""
    attempt: int = 0
    max_attempts: int = 3


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

    def update(self, task_key: str, status: TaskStatus, message: str = "") -> None:
        """Update task status and counters."""
        if task_key in self.tasks:
            old_status = self.tasks[task_key].status
            self.tasks[task_key].status = status
            self.tasks[task_key].message = message

            # Update counters only on state transitions to completed states
            if old_status not in (
                TaskStatus.SUCCESS,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
            ):
                if status == TaskStatus.SUCCESS:
                    self.completed += 1
                    self.succeeded += 1
                elif status == TaskStatus.FAILED:
                    self.completed += 1
                    self.failed += 1
                elif status == TaskStatus.CANCELLED:
                    self.completed += 1
                    self.cancelled += 1


@dataclass
class RateLimiter:
    """Token bucket rate limiter for API requests.

    Let's Encrypt limits:
    - 20 requests/second for new-reg, new-authz, new-cert
    - 300 pending authorizations per account
    - 5 duplicate certificates per week
    """

    rate: float = 10.0  # requests per second (conservative default)
    burst_size: int = 5
    tokens: float = field(init=False)
    last_update: float = field(init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        """Initialize mutable state after dataclass creation."""
        self.tokens = float(self.burst_size)
        self.last_update = time.monotonic()

    def acquire(self, timeout: float = 30.0) -> bool:
        """Acquire a token, blocking until available or timeout."""
        deadline = time.monotonic() + timeout

        while True:
            with self._lock:
                now = time.monotonic()
                # Refill tokens based on elapsed time
                elapsed = now - self.last_update
                self.tokens = min(self.burst_size, self.tokens + elapsed * self.rate)
                self.last_update = now

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True

            # Check timeout
            if time.monotonic() >= deadline:
                return False

            # Wait a bit before retrying
            time.sleep(0.1)


@dataclass
class WorkItem:
    """A single unit of work for the executor."""

    domain_config: DomainConfig
    key_type: KeyType
    config: LemattConfig
    domain_actions: DomainActions

    @property
    def task_key(self) -> str:
        return f"{self.domain_config.primary_domain}:{self.key_type}"


def _worker_init() -> None:
    """Initialize worker processes to ignore SIGINT.

    Worker processes should ignore SIGINT (Ctrl-C) since the parent
    process handles shutdown coordination. This prevents ugly tracebacks
    from worker processes when the user interrupts the program.
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _process_certificate_worker(
    domain_config: DomainConfig,
    key_type: KeyType,
    config: LemattConfig,
    domain_actions: DomainActions,
) -> list[dict[str, object]]:
    """Worker function for processing a domain with ALL key types.

    This function runs in a separate process and must be a top-level
    function (not a method or lambda) for proper pickling.

    CRITICAL: Processes ALL key types (RSA + EC) together with shared prepare
    processes to prevent "port already in use" errors.

    Returns a list of serializable dicts (via WorkerResult.to_dict()) to avoid
    pickling issues with complex objects across process boundaries.
    """
    # Import here to avoid circular imports and ensure fresh state in worker
    from lematt.manager import CertificateManager

    try:
        manager = CertificateManager(config)
        # Process entire domain with all key types (prepare runs ONCE)
        results = manager.process_domain_all_keys(domain_config, domain_actions)

        return [
            WorkerResult(
                domain=result.domain,
                key_type=str(result.key_type),
                success=result.success,
                renewed=result.renewed,
                cert_path=result.cert_path,
                key_path=result.key_path,
                error_message=result.error_message,
                all_domains=domain_config.all_domains,
            ).to_dict()
            for result in results
        ]
    except Exception as e:
        # Catch ALL exceptions to prevent worker crashes from propagating
        # Return failures for both key types
        return [
            WorkerResult(
                domain=domain_config.primary_domain,
                key_type=str(kt),
                success=False,
                renewed=True,  # We tried to renew
                error_message=f"Worker exception: {e!s}",
                all_domains=domain_config.all_domains,
                exception=str(e),
            ).to_dict()
            for kt in [KeyType.RSA, KeyType.EC]
        ]


@dataclass
class CertificateExecutor:
    """Robust concurrent executor for certificate operations.

    Features:
    - Error isolation: Individual task failures don't affect others
    - Rate limiting: Respects Let's Encrypt API limits
    - Progress tracking: Real-time visibility into batch operations
    - Graceful shutdown: Clean cancellation on interrupt
    - Memory efficient: Processes results as they complete
    """

    config: LemattConfig
    max_workers: int | None = None
    rate_limit: float = 10.0
    progress_callback: Callable[[BatchProgress], None] | None = None

    # Internal state with clean defaults
    progress: BatchProgress = field(default_factory=BatchProgress)
    _summary: RenewalSummary = field(default_factory=RenewalSummary, repr=False)
    _shutdown_event: threading.Event = field(
        default_factory=threading.Event, repr=False
    )
    _signal_count: int = field(default=0, repr=False)
    _original_sigint: signal.Handlers | None = field(default=None, repr=False)
    _original_sigterm: signal.Handlers | None = field(default=None, repr=False)
    _executor: ProcessPoolExecutor | None = field(default=None, repr=False)

    # Computed fields (require __post_init__)
    rate_limiter: RateLimiter = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Initialize computed fields after dataclass creation."""
        # Cap max_workers at 10
        if self.max_workers is None:
            self.max_workers = min(self.config.concurrency, 10)
        else:
            self.max_workers = min(self.max_workers, 10)

        # Create rate limiter with configured rate
        self.rate_limiter = RateLimiter(rate=self.rate_limit)

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        self._original_sigint = signal.signal(signal.SIGINT, self._signal_handler)
        self._original_sigterm = signal.signal(signal.SIGTERM, self._signal_handler)

    def _restore_signal_handlers(self) -> None:
        """Restore original signal handlers."""
        if self._original_sigint is not None:
            signal.signal(signal.SIGINT, self._original_sigint)
        if self._original_sigterm is not None:
            signal.signal(signal.SIGTERM, self._original_sigterm)

    def _signal_handler(self, signum: int, frame: object) -> None:
        """Handle shutdown signals gracefully.

        First signal: Set shutdown event for graceful cleanup.
        Second signal: Force immediate executor shutdown and raise KeyboardInterrupt.
        """
        self._signal_count += 1

        if self._signal_count == 1:
            logger.warning(
                f"Received signal {signum} - graceful shutdown initiated. "
                "Press Ctrl-C again to force immediate exit."
            )
            self._shutdown_event.set()
        else:
            logger.error(
                f"Received signal {signum} again ({self._signal_count} times) - "
                "forcing immediate exit!"
            )
            # Forcefully shut down the executor if it exists
            if self._executor is not None:
                logger.warning("Forcefully terminating worker processes...")
                try:
                    # Cancel all pending futures and don't wait for workers
                    self._executor.shutdown(wait=False, cancel_futures=True)
                except Exception as e:
                    logger.error(f"Error during forced shutdown: {e}")

            # Restore original handlers
            self._restore_signal_handlers()
            # Raise KeyboardInterrupt to let cli.py handle cleanup
            raise KeyboardInterrupt("Forced shutdown by user")

    def _log_progress(self) -> None:
        """Log current progress with domain lists."""
        p = self.progress

        # Build lists of domains by status
        successful = []
        failed = []
        in_progress = []
        pending = []

        for task_key, task in p.tasks.items():
            # Extract domain name from task_key (format: "domain.com:rsa" or "domain.com:ec")
            domain = task.domain
            key_type = task.key_type

            if task.status == TaskStatus.SUCCESS:
                successful.append(f"{domain}[{key_type}]")
            elif task.status == TaskStatus.FAILED:
                failed.append(f"{domain}[{key_type}]")
            elif task.status == TaskStatus.RUNNING:
                in_progress.append(f"{domain}[{key_type}]")
            elif task.status == TaskStatus.PENDING:
                pending.append(f"{domain}[{key_type}]")

        # Format the lists for display - SHOW ALL
        success_list = ", ".join(successful)
        failed_list = ", ".join(failed)
        in_progress_list = ", ".join(in_progress)
        pending_list = ", ".join(pending)

        # Log progress with COMPLETE lists
        logger.info(
            f"Progress: {p.completed}/{p.total} ({p.percent_complete:.1f}%) - "
            f"Success: {p.succeeded}, Failed: {p.failed}, "
            f"In-Progress: {len(in_progress)}, Pending: {len(pending)}"
        )

        if successful:
            logger.info(f"  ✓ Successful: {success_list}")
        if failed:
            logger.warning(f"  ✗ Failed: {failed_list}")
        if in_progress:
            logger.info(f"  ▶ In-Progress: {in_progress_list}")
        if pending:
            logger.info(f"  ⏳ Pending: {pending_list}")

        if self.progress_callback:
            self.progress_callback(p)

    def process_batch(
        self,
        domains: list[DomainConfig],
        domain_actions: DomainActions,
    ) -> RenewalSummary:
        """Process a batch of domains with both RSA and EC certificates.

        Args:
            domains: List of domain configurations to process.
            domain_actions: Action configuration for domains.

        Returns:
            RenewalSummary with all results.
        """
        # Build work items - one per DOMAIN (not per key type)
        # This ensures prepare actions run once per domain and stay alive for all key types
        work_items: list[WorkItem] = []
        for domain_config in domains:
            # Process entire domain (both RSA and EC) as a single work unit
            # to prevent concurrent prepare actions
            work_items.append(
                WorkItem(
                    domain_config=domain_config,
                    key_type=KeyType.RSA,  # Placeholder - will process all key types
                    config=self.config,
                    domain_actions=domain_actions,
                )
            )

        # Initialize progress tracking and summary
        # Note: Total is domains * 2 (RSA + EC per domain)
        self.progress = BatchProgress(total=len(work_items) * 2)
        self._summary = RenewalSummary()
        for item in work_items:
            # Track both RSA and EC for each domain
            for key_type in [KeyType.RSA, KeyType.EC]:
                task_key = f"{item.domain_config.primary_domain}[{key_type}]"
                self.progress.tasks[task_key] = TaskProgress(
                    domain=item.domain_config.primary_domain,
                    key_type=key_type,
                )

        if self.max_workers <= 1:
            # Sequential processing
            return self._process_sequential(work_items, domain_actions)

        # Parallel processing with proper error handling
        return self._process_parallel(work_items, domains)

    def _process_sequential(
        self,
        work_items: list[WorkItem],
        domain_actions: DomainActions,
    ) -> RenewalSummary:
        """Process work items sequentially."""
        from lematt.manager import CertificateManager

        self._setup_signal_handlers()

        try:
            manager = CertificateManager(self.config)

            for item in work_items:
                # Check shutdown BEFORE starting each domain
                if self._shutdown_event.is_set():
                    # Cancel all key types for this domain
                    for key_type in [KeyType.RSA, KeyType.EC]:
                        task_key = f"{item.domain_config.primary_domain}[{key_type}]"
                        logger.info(f"Skipping {task_key} due to shutdown request")
                        self.progress.update(task_key, TaskStatus.CANCELLED)
                    continue

                logger.info(
                    f"▶ Starting domain: {item.domain_config.primary_domain} (RSA + EC)"
                )

                # Update progress for both key types
                for key_type in [KeyType.RSA, KeyType.EC]:
                    task_key = f"{item.domain_config.primary_domain}[{key_type}]"
                    self.progress.update(task_key, TaskStatus.RUNNING)
                self._log_progress()

                try:
                    # Process entire domain with all key types (prepare runs ONCE)
                    results = manager.process_domain_all_keys(
                        item.domain_config,
                        domain_actions,
                    )

                    # Add all results and update progress
                    for result in results:
                        self._summary.add_result(result)
                        task_key = (
                            f"{result.domain_config.primary_domain}[{result.key_type}]"
                        )

                        if result.success:
                            self.progress.update(task_key, TaskStatus.SUCCESS)
                            if result.renewed:
                                logger.success(
                                    f"✓ Renewed: {result.domain_config.primary_domain} [{result.key_type}]"
                                )
                            else:
                                logger.info(
                                    f"✓ Valid: {result.domain_config.primary_domain} [{result.key_type}] (skipped)"
                                )
                        else:
                            self.progress.update(
                                task_key,
                                TaskStatus.FAILED,
                                result.error_message or "Unknown error",
                            )
                            logger.error(
                                f"✗ Failed: {result.domain_config.primary_domain} [{result.key_type}] - "
                                f"{result.error_message or 'Unknown error'}"
                            )

                    # Check shutdown AFTER completing each domain
                    if self._shutdown_event.is_set():
                        logger.info("Shutdown requested - stopping batch processing")
                        break

                except KeyboardInterrupt:
                    # Signal handler should have caught this, but if not,
                    # set shutdown event and stop immediately
                    logger.warning(
                        f"Interrupted during {item.task_key}, stopping immediately"
                    )
                    self._shutdown_event.set()
                    self.progress.update(
                        item.task_key, TaskStatus.CANCELLED, "Interrupted by user"
                    )
                    break

            self._log_progress()
            return self._summary
        finally:
            self._restore_signal_handlers()

    def _process_parallel(
        self,
        work_items: list[WorkItem],
        domains: list[DomainConfig],
    ) -> RenewalSummary:
        """Process work items in parallel with error isolation."""
        self._setup_signal_handlers()

        # Initialize domain locks to prevent concurrent prepare actions per domain
        _init_domain_locks()

        # Create domain lookup for result reconstruction
        domain_lookup = {d.primary_domain: d for d in domains}

        try:
            with ProcessPoolExecutor(
                max_workers=self.max_workers, initializer=_worker_init
            ) as executor:
                # Store executor reference for forced shutdown
                self._executor = executor

                # Submit all tasks with rate limiting
                future_to_item: dict[Future, WorkItem] = {}

                for item in work_items:
                    if self._shutdown_event.is_set():
                        break

                    # Rate limit submissions
                    if not self.rate_limiter.acquire(timeout=60.0):
                        logger.warning(f"Rate limit timeout for {item.task_key}")
                        continue

                    self.progress.update(item.task_key, TaskStatus.RUNNING)
                    logger.info(
                        f"▶ Starting: {item.domain_config.primary_domain} [{item.key_type}]"
                    )

                    future = executor.submit(
                        _process_certificate_worker,
                        item.domain_config,
                        item.key_type,
                        item.config,
                        item.domain_actions,
                    )
                    future_to_item[future] = item

                # Process results as they complete with periodic progress updates
                last_progress_time = time.monotonic()
                progress_interval = 10.0  # Log every 10 seconds if no activity
                completed_futures = set()

                while len(completed_futures) < len(future_to_item):
                    if self._shutdown_event.is_set():
                        # Cancel remaining futures
                        for f in future_to_item:
                            f.cancel()
                        break

                    # Check if we should log periodic progress even without completion
                    now = time.monotonic()
                    if now - last_progress_time >= progress_interval:
                        logger.info("⏳ Still processing certificates...")
                        self._log_progress()
                        last_progress_time = now

                    # Wait for next completion with timeout for periodic updates
                    try:
                        for future in as_completed(future_to_item, timeout=1.0):
                            if future in completed_futures:
                                continue
                            completed_futures.add(future)

                            item = future_to_item[future]
                            last_progress_time = (
                                time.monotonic()
                            )  # Reset timer on activity

                            try:
                                # Worker now returns list of results (one per key type)
                                result_dicts = future.result(timeout=300)
                                for result_dict in result_dicts:
                                    result = self._dict_to_result(
                                        result_dict, domain_lookup
                                    )
                                    self._summary.add_result(result)

                                    task_key = f"{result.domain_config.primary_domain}[{result.key_type}]"

                                    if result.success:
                                        self.progress.update(
                                            task_key, TaskStatus.SUCCESS
                                        )
                                        if result.renewed:
                                            logger.success(
                                                f"✓ Renewed: {result.domain_config.primary_domain} [{result.key_type}]"
                                            )
                                        else:
                                            logger.info(
                                                f"✓ Valid: {result.domain_config.primary_domain} [{result.key_type}] (skipped)"
                                            )
                                    else:
                                        self.progress.update(
                                            task_key,
                                            TaskStatus.FAILED,
                                            result.error_message or "Unknown error",
                                        )
                                        logger.error(
                                            f"✗ Failed: {result.domain_config.primary_domain} [{result.key_type}] - "
                                            f"{result.error_message or 'Unknown error'}"
                                        )
                            except TimeoutError:
                                logger.error(
                                    f"Timeout processing domain {item.domain_config.primary_domain}"
                                )
                                # Mark both key types as failed
                                for key_type in [KeyType.RSA, KeyType.EC]:
                                    task_key = f"{item.domain_config.primary_domain}[{key_type}]"
                                    self.progress.update(
                                        task_key, TaskStatus.FAILED, "Timeout"
                                    )
                                    self._summary.add_result(
                                        CertificateResult(
                                            domain_config=item.domain_config,
                                            key_type=key_type,
                                            success=False,
                                            renewed=True,
                                            error_message="Processing timeout",
                                        )
                                    )
                            except Exception as e:
                                logger.error(
                                    f"Error processing domain {item.domain_config.primary_domain}: {e}"
                                )
                                # Mark both key types as failed
                                for key_type in [KeyType.RSA, KeyType.EC]:
                                    task_key = f"{item.domain_config.primary_domain}[{key_type}]"
                                    self.progress.update(
                                        task_key, TaskStatus.FAILED, str(e)
                                    )
                                    self._summary.add_result(
                                        CertificateResult(
                                            domain_config=item.domain_config,
                                            key_type=key_type,
                                            success=False,
                                            renewed=True,
                                            error_message=f"Executor error: {e}",
                                        )
                                    )

                            self._log_progress()
                            break  # Process one future at a time
                    except TimeoutError:
                        # No futures completed in this interval, continue waiting
                        pass

        finally:
            self._executor = None  # Clear executor reference
            self._restore_signal_handlers()
            # Shutdown domain lock manager
            _shutdown_domain_locks()

        return self._summary

    def _dict_to_result(
        self,
        result_dict: dict[str, object],
        domain_lookup: dict[str, DomainConfig],
    ) -> CertificateResult:
        """Convert worker result dict back to CertificateResult."""
        worker_result = WorkerResult.from_dict(result_dict)
        domain_config = domain_lookup.get(worker_result.domain)

        if domain_config is None:
            # Fallback: create minimal domain config
            domain_config = DomainConfig(primary_domain=worker_result.domain)

        return CertificateResult(
            domain_config=domain_config,
            key_type=KeyType.from_string(worker_result.key_type),
            success=worker_result.success,
            renewed=worker_result.renewed,
            cert_path=worker_result.cert_path,
            key_path=worker_result.key_path,
            error_message=worker_result.error_message,
        )


def create_progress_printer(verbose: bool = False) -> Callable[[BatchProgress], None]:
    """Create a progress callback that prints to console.

    Args:
        verbose: Whether to show detailed per-task progress.

    Returns:
        Progress callback function.
    """

    def printer(progress: BatchProgress) -> None:
        if verbose:
            for task_key, task in progress.tasks.items():
                if task.status == TaskStatus.RUNNING:
                    logger.debug(f"  [{task_key}] {task.status.name}")

    return printer

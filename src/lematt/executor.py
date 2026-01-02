"""Concurrent certificate processing with reliability guarantees.

This module provides a robust executor for parallel certificate operations
with proper error isolation, rate limiting, progress tracking, and graceful
shutdown handling.
"""

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


def _process_certificate_worker(
    domain_config: DomainConfig,
    key_type: KeyType,
    config: LemattConfig,
    domain_actions: DomainActions,
) -> dict[str, object]:
    """Worker function for processing a single certificate.

    This function runs in a separate process and must be a top-level
    function (not a method or lambda) for proper pickling.

    Returns a serializable dict (via WorkerResult.to_dict()) to avoid
    pickling issues with complex objects across process boundaries.
    """
    # Import here to avoid circular imports and ensure fresh state in worker
    from lematt.manager import CertificateManager

    try:
        manager = CertificateManager(config)
        result = manager.process_domain(domain_config, key_type, domain_actions)

        return WorkerResult(
            domain=result.domain,
            key_type=str(result.key_type),
            success=result.success,
            renewed=result.renewed,
            cert_path=result.cert_path,
            key_path=result.key_path,
            error_message=result.error_message,
            all_domains=domain_config.all_domains,
        ).to_dict()
    except Exception as e:
        # Catch ALL exceptions to prevent worker crashes from propagating
        return WorkerResult(
            domain=domain_config.primary_domain,
            key_type=str(key_type),
            success=False,
            renewed=True,  # We tried to renew
            error_message=f"Worker exception: {e!s}",
            all_domains=domain_config.all_domains,
            exception=str(e),
        ).to_dict()


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
    _original_sigint: signal.Handlers | None = field(default=None, repr=False)
    _original_sigterm: signal.Handlers | None = field(default=None, repr=False)

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
        """Handle shutdown signals gracefully."""
        logger.warning(f"Received signal {signum}, initiating graceful shutdown...")
        self._shutdown_event.set()

    def _log_progress(self) -> None:
        """Log current progress."""
        p = self.progress
        logger.info(
            f"Progress: {p.completed}/{p.total} "
            f"({p.percent_complete:.1f}%) - "
            f"Success: {p.succeeded}, Failed: {p.failed}"
        )
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
        # Build work items
        work_items: list[WorkItem] = []
        for domain_config in domains:
            for key_type in [KeyType.RSA, KeyType.EC]:
                work_items.append(
                    WorkItem(
                        domain_config=domain_config,
                        key_type=key_type,
                        config=self.config,
                        domain_actions=domain_actions,
                    )
                )

        # Initialize progress tracking and summary
        self.progress = BatchProgress(total=len(work_items))
        self._summary = RenewalSummary()
        for item in work_items:
            self.progress.tasks[item.task_key] = TaskProgress(
                domain=item.domain_config.primary_domain,
                key_type=item.key_type,
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
                if self._shutdown_event.is_set():
                    logger.info(f"Skipping {item.task_key} due to shutdown request")
                    self.progress.update(item.task_key, TaskStatus.CANCELLED)
                    continue

                self.progress.update(item.task_key, TaskStatus.RUNNING)
                self._log_progress()

                try:
                    result = manager.process_domain(
                        item.domain_config,
                        item.key_type,
                        domain_actions,
                    )
                    self._summary.add_result(result)

                    if result.success:
                        self.progress.update(item.task_key, TaskStatus.SUCCESS)
                    else:
                        self.progress.update(
                            item.task_key,
                            TaskStatus.FAILED,
                            result.error_message or "Unknown error",
                        )
                except KeyboardInterrupt:
                    # Signal handler should have caught this, but if not,
                    # set shutdown event and continue to allow graceful cleanup
                    logger.warning(
                        f"Interrupted during {item.task_key}, stopping after current batch"
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

        # Create domain lookup for result reconstruction
        domain_lookup = {d.primary_domain: d for d in domains}

        try:
            with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
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

                    future = executor.submit(
                        _process_certificate_worker,
                        item.domain_config,
                        item.key_type,
                        item.config,
                        item.domain_actions,
                    )
                    future_to_item[future] = item

                # Process results as they complete
                for future in as_completed(future_to_item):
                    if self._shutdown_event.is_set():
                        # Cancel remaining futures
                        for f in future_to_item:
                            f.cancel()
                        break

                    item = future_to_item[future]

                    try:
                        result_dict = future.result(
                            timeout=300
                        )  # 5 minute timeout per cert
                        result = self._dict_to_result(result_dict, domain_lookup)
                        self._summary.add_result(result)

                        if result.success:
                            self.progress.update(item.task_key, TaskStatus.SUCCESS)
                        else:
                            self.progress.update(
                                item.task_key,
                                TaskStatus.FAILED,
                                result.error_message or "Unknown error",
                            )
                    except TimeoutError:
                        logger.error(f"Timeout processing {item.task_key}")
                        self.progress.update(
                            item.task_key, TaskStatus.FAILED, "Timeout"
                        )
                        self._summary.add_result(
                            CertificateResult(
                                domain_config=item.domain_config,
                                key_type=item.key_type,
                                success=False,
                                renewed=True,
                                error_message="Processing timeout",
                            )
                        )
                    except Exception as e:
                        logger.error(f"Error processing {item.task_key}: {e}")
                        self.progress.update(item.task_key, TaskStatus.FAILED, str(e))
                        self._summary.add_result(
                            CertificateResult(
                                domain_config=item.domain_config,
                                key_type=item.key_type,
                                success=False,
                                renewed=True,
                                error_message=f"Executor error: {e}",
                            )
                        )

                    self._log_progress()

        finally:
            self._restore_signal_handlers()

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

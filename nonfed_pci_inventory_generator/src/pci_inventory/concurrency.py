"""Parallelism, rate-limit safety, and error capture.

Building blocks:
- :class:`TokenBucket` — a thread-safe global rate limiter. Every AWS call passes
  through it, so total request rate stays under a sustained ceiling regardless of
  how many workers run.
- :class:`ErrorCollector` — thread-safe accumulator for per-call/per-resource
  failures, surfaced later in the Errors/Exceptions sheet so missing data is
  always visible and explained.
- :class:`ServiceThrottleGate` — per-service-class semaphores so hard-throttling
  services (IAM, Config, CloudTrail, Organizations, API Gateway) run at low
  concurrency even when the global pool is large.
- :func:`run_work_units` — bounded thread-pool fan-out over (account × region ×
  service) work units, with isolated error handling: one failing unit never
  aborts the run.
- :func:`safe_paginate` / :func:`call` — wrappers that acquire a rate-limit
  token, execute, and record throttling/abort stats.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Sequence

from botocore.exceptions import ClientError, EndpointConnectionError

from pci_inventory.utils import iso_now

logger = logging.getLogger("pci_inventory.concurrency")

# Error codes that indicate throttling/rate limiting across AWS services.
THROTTLE_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "RequestLimitExceeded",
        "RequestThrottled",
        "TooManyRequestsException",
        "RequestThrottledException",
        "SlowDown",
        "ProvisionedThroughputExceededException",
        "LimitExceededException",
    }
)

# Error codes that mean "this service/region isn't usable here" — recorded, not fatal.
BENIGN_UNAVAILABLE_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "AuthorizationError",
        "OptInRequired",
        "SubscriptionRequiredException",
        "InvalidClientTokenId",
        "UnrecognizedClientException",
        "InvalidAction",
    }
)


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
class TokenBucket:
    """A simple thread-safe token-bucket rate limiter.

    Tokens refill at ``rate`` per second up to ``capacity``. :meth:`acquire`
    blocks until a token is available. This complements boto3's adaptive retry by
    capping the *aggregate* request rate across all worker threads.
    """

    def __init__(self, rate: float, capacity: float) -> None:
        self._rate = max(rate, 0.1)
        self._capacity = max(capacity, 1.0)
        self._tokens = self._capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> None:
        """Block until ``tokens`` are available, then consume them."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                wait = deficit / self._rate
            time.sleep(min(wait, 1.0))

    def penalize(self, seconds: float = 1.0) -> None:
        """Drain tokens to back off after a throttling response."""
        with self._lock:
            self._tokens = max(0.0, self._tokens - seconds * self._rate)


class _ReentrantGate:
    """A counting semaphore that is **reentrant per thread**.

    A worker thread that already holds the gate may re-acquire it for free
    (tracked by a per-thread hold-depth); the underlying permit is only consumed
    on the first acquire and only released when the matching outermost release
    runs. This keeps the cross-thread concurrency cap intact (only *distinct*
    threads consume permits) while making **nested same-thread acquisitions safe**.

    This matters because :meth:`CallContext.paginate` holds the gate for the whole
    duration a collector iterates its pages, and some hard-throttle collectors
    (e.g. Organizations: ``list_policies`` → ``describe_policy`` /
    ``list_targets_for_policy``) make further gated calls *while iterating*. With a
    plain non-reentrant semaphore those nested acquires self-block, and once every
    permit is held by a thread waiting on the same gate the whole run deadlocks.
    """

    def __init__(self, cap: int) -> None:
        self._sem = threading.BoundedSemaphore(max(cap, 1))
        self._local = threading.local()

    def acquire(self) -> None:
        depth = getattr(self._local, "depth", 0)
        if depth == 0:
            self._sem.acquire()
        self._local.depth = depth + 1

    def release(self) -> None:
        depth = getattr(self._local, "depth", 0)
        if depth <= 0:
            # Defensive: never under-release the underlying semaphore.
            return
        depth -= 1
        self._local.depth = depth
        if depth == 0:
            self._sem.release()


class ServiceThrottleGate:
    """Per-service-class concurrency caps via semaphores.

    Hard-throttling services share a small semaphore; medium services a larger
    one; everything else is uncapped (bounded only by the global thread pool).
    The gates are **per-thread reentrant** (see :class:`_ReentrantGate`) so a
    collector that makes a gated call while already holding the gate (nested
    pagination) cannot self-deadlock.
    """

    def __init__(self, hard_services: Sequence[str], hard_cap: int, medium_cap: int) -> None:
        self._hard_services = set(hard_services)
        self._hard = _ReentrantGate(hard_cap)
        self._medium = _ReentrantGate(medium_cap)
        # Medium-class services (others are uncapped at this layer).
        self._medium_services = {
            "ec2", "rds", "lambda", "elbv2", "elb", "kms", "s3", "dynamodb",
            "logs", "cloudwatch", "secretsmanager", "ecs", "ecr", "sns", "sqs",
        }

    def gate_for(self, service: str) -> _ReentrantGate | None:
        if service in self._hard_services:
            return self._hard
        if service in self._medium_services:
            return self._medium
        return None


# --------------------------------------------------------------------------- #
# Error capture
# --------------------------------------------------------------------------- #
@dataclass
class CollectionError:
    """A single captured error for the Errors/Exceptions report."""

    account_id: str
    region: str
    service: str
    operation: str
    error_code: str
    message: str
    resource_id: str = ""
    timestamp_utc: str = field(default_factory=iso_now)

    def to_dict(self) -> dict[str, str]:
        return {
            "account_id": self.account_id,
            "region": self.region,
            "service": self.service,
            "operation": self.operation,
            "resource_id": self.resource_id,
            "error_code": self.error_code,
            "message": self.message,
            "timestamp_utc": self.timestamp_utc,
        }


class ErrorCollector:
    """Thread-safe accumulator for collection errors + throttling statistics."""

    def __init__(self) -> None:
        self._errors: list[CollectionError] = []
        self._lock = threading.Lock()
        self._throttle_events = 0

    def record(self, err: CollectionError) -> None:
        with self._lock:
            self._errors.append(err)

    def record_throttle(self) -> None:
        with self._lock:
            self._throttle_events += 1

    @property
    def errors(self) -> list[CollectionError]:
        with self._lock:
            return sorted(
                self._errors,
                key=lambda e: (e.account_id, e.region, e.service, e.operation),
            )

    @property
    def count(self) -> int:
        """Number of captured errors so far (cheap; for live progress)."""
        with self._lock:
            return len(self._errors)

    def recent(self, n: int) -> list[CollectionError]:
        """The most recently captured ``n`` errors, in capture order.

        Insertion order (not sorted) so a live display shows issues as they
        actually surfaced during the run.
        """
        with self._lock:
            return list(self._errors[-n:]) if n > 0 else []

    @property
    def throttle_events(self) -> int:
        with self._lock:
            return self._throttle_events


# --------------------------------------------------------------------------- #
# Call context — threads the rate limiter, gate, and error collector together.
# --------------------------------------------------------------------------- #
@dataclass
class CallContext:
    """Per-run context passed to collectors for safe, rate-limited AWS calls."""

    bucket: TokenBucket
    gate: ServiceThrottleGate
    errors: ErrorCollector

    def call(
        self,
        func: Callable[..., Any],
        *,
        account_id: str,
        region: str,
        service: str,
        operation: str,
        resource_id: str = "",
        default: Any = None,
        reraise: bool = False,
        **kwargs: Any,
    ) -> Any:
        """Invoke a boto3 call through the rate limiter with error capture.

        Returns ``func(**kwargs)`` on success. On a captured error, records it and
        returns ``default`` (or re-raises if ``reraise``). Throttling is retried a
        few times with backoff on top of boto3's own adaptive retries.

        The per-service throttle gate is acquired for the whole call (incl.
        retries) so hard-throttling services (IAM/Config/CloudTrail/Org/API GW)
        stay within their concurrency cap even for single-shot calls — not just
        paginated ones.
        """
        gate = self.gate.gate_for(service)
        if gate is not None:
            gate.acquire()
        try:
            return self._call_inner(
                func, account_id=account_id, region=region, service=service,
                operation=operation, resource_id=resource_id, default=default,
                reraise=reraise, **kwargs,
            )
        finally:
            if gate is not None:
                gate.release()

    def _call_inner(
        self,
        func: Callable[..., Any],
        *,
        account_id: str,
        region: str,
        service: str,
        operation: str,
        resource_id: str = "",
        default: Any = None,
        reraise: bool = False,
        **kwargs: Any,
    ) -> Any:
        attempts = 0
        while True:
            attempts += 1
            self.bucket.acquire()
            try:
                return func(**kwargs)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "ClientError")
                if code in THROTTLE_CODES and attempts <= 5:
                    self.errors.record_throttle()
                    self.bucket.penalize(seconds=float(attempts))
                    backoff = min(2.0 ** attempts, 20.0)
                    logger.debug("Throttled on %s:%s (attempt %d), backing off %.1fs",
                                 service, operation, attempts, backoff)
                    time.sleep(backoff)
                    continue
                self.errors.record(
                    CollectionError(account_id, region, service, operation, code,
                                    str(exc), resource_id)
                )
                if reraise:
                    raise
                return default
            except EndpointConnectionError as exc:
                self.errors.record(
                    CollectionError(account_id, region, service, operation,
                                    "EndpointConnectionError", str(exc), resource_id)
                )
                if reraise:
                    raise
                return default
            except Exception as exc:  # noqa: BLE001 - never let one call abort the run
                self.errors.record(
                    CollectionError(account_id, region, service, operation,
                                    type(exc).__name__, str(exc), resource_id)
                )
                if reraise:
                    raise
                return default

    def paginate(
        self,
        client: Any,
        operation: str,
        *,
        account_id: str,
        region: str,
        service: str,
        result_key: str | None = None,
        **kwargs: Any,
    ) -> Iterator[Any]:
        """Yield items (or pages) from a paginated boto3 operation, rate-limited.

        If ``result_key`` is given, yields the flattened items from that key on
        each page; otherwise yields whole page dicts. Errors are captured and end
        iteration gracefully.
        """
        gate = self.gate.gate_for(service)
        if not client.can_paginate(operation):
            # Fall back to a single call.
            page = self.call(
                getattr(client, operation),
                account_id=account_id, region=region, service=service,
                operation=operation, default=None, **kwargs,
            )
            if page is None:
                return
            if result_key:
                yield from page.get(result_key, [])
            else:
                yield page
            return

        paginator = client.get_paginator(operation)
        try:
            if gate is not None:
                gate.acquire()
            try:
                page_iter = paginator.paginate(**kwargs)
                for page in _rate_limited_pages(page_iter, self.bucket):
                    if result_key:
                        yield from page.get(result_key, [])
                    else:
                        yield page
            finally:
                if gate is not None:
                    gate.release()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "ClientError")
            self.errors.record(
                CollectionError(account_id, region, service, operation, code, str(exc))
            )
        except Exception as exc:  # noqa: BLE001
            self.errors.record(
                CollectionError(account_id, region, service, operation,
                                type(exc).__name__, str(exc))
            )

    def paginate_token(
        self,
        func: Callable[..., Any],
        *,
        account_id: str,
        region: str,
        service: str,
        operation: str,
        result_key: str,
        request_token_param: str,
        response_token_field: str,
        **kwargs: Any,
    ) -> Iterator[Any]:
        """Manual continuation-token pagination for APIs without a boto3 paginator.

        Used for services whose list operations paginate but have no registered
        paginator (e.g. ``wafv2:ListWebACLs`` with NextMarker, ``apigatewayv2:GetApis``
        with NextToken). Each page is fetched through :meth:`call` (rate-limited,
        gated, error-captured). Stops when the response token is absent.
        """
        token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            call_kwargs = dict(kwargs)
            if token is not None:
                call_kwargs[request_token_param] = token
            resp = self.call(
                func, account_id=account_id, region=region, service=service,
                operation=operation, default=None, **call_kwargs,
            )
            if resp is None:
                return
            yield from resp.get(result_key, [])
            token = resp.get(response_token_field)
            if not token or token in seen_tokens:
                return
            seen_tokens.add(token)


def _rate_limited_pages(page_iter: Iterator[Any], bucket: TokenBucket) -> Iterator[Any]:
    """Acquire a token before each page fetch from a botocore paginator."""
    iterator = iter(page_iter)
    while True:
        bucket.acquire()
        try:
            yield next(iterator)
        except StopIteration:
            return


# --------------------------------------------------------------------------- #
# Work-unit fan-out
# --------------------------------------------------------------------------- #
@dataclass
class WorkUnit:
    """A unit of collection work: run one collector for one account+region."""

    account_id: str
    region: str
    service: str
    label: str
    fn: Callable[[], list[Any]]


def run_work_units(
    units: Sequence[WorkUnit],
    max_workers: int,
    on_unit_done: Callable[[int, int, WorkUnit, int], None] | None = None,
    on_unit_start: Callable[[WorkUnit], None] | None = None,
    on_unit_end: Callable[[WorkUnit], None] | None = None,
) -> list[Any]:
    """Run work units on a bounded thread pool, isolating per-unit failures.

    Each unit returns a list of records; results are concatenated. A unit that
    raises is logged and contributes nothing — it never aborts the run.

    Progress callbacks (all optional; any exception they raise is suppressed so
    the UI can never abort a collection run):

    - ``on_unit_start(unit)`` / ``on_unit_end(unit)`` fire **inside the worker
      thread** immediately around ``unit.fn()``, so a live display can show what
      each worker is doing *right now*. They MUST be thread-safe.
    - ``on_unit_done(done, total, unit, n_records)`` fires on the main thread as
      each future completes (drives the overall counter/bar); need not be
      thread-safe.
    """
    results: list[Any] = []
    if not units:
        return results

    workers = max(1, min(max_workers, len(units)))
    logger.info("Running %d work units across %d workers", len(units), workers)

    def _wrapped(u: WorkUnit) -> list[Any]:
        if on_unit_start is not None:
            try:
                on_unit_start(u)
            except Exception:  # noqa: BLE001 - the UI must never abort a run
                pass
        try:
            return u.fn()
        finally:
            if on_unit_end is not None:
                try:
                    on_unit_end(u)
                except Exception:  # noqa: BLE001
                    pass

    total = len(units)
    done = 0
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pci-wkr") as pool:
        future_map = {pool.submit(_wrapped, u): u for u in units}
        for fut in as_completed(future_map):
            unit = future_map[fut]
            n_records = 0
            try:
                records = fut.result()
                if records:
                    results.extend(records)
                    n_records = len(records)
                logger.debug("Unit done: %s [%s/%s] -> %d records",
                             unit.label, unit.account_id, unit.region, n_records)
            except Exception as exc:  # noqa: BLE001 - isolated failure
                logger.error("Work unit failed (%s %s/%s): %s",
                             unit.label, unit.account_id, unit.region, exc)
            done += 1
            if on_unit_done is not None:
                try:
                    on_unit_done(done, total, unit, n_records)
                except Exception:  # noqa: BLE001 - the UI must never abort a run
                    pass
    return results

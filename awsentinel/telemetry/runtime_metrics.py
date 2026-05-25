import asyncio
import time
from dataclasses import dataclass
from typing import AsyncIterator


@dataclass(frozen=True)
class MetricSnapshot:
    concurrent_tasks: int
    pending_tasks: int
    api_calls: int
    api_calls_per_second: float
    retry_count: int
    throttling_count: int
    average_api_latency: float
    api_errors_count: int
    partial_failures: int


class RuntimeMetrics:
    """Lightweight async-safe runtime counters for a scan."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._started_at = time.perf_counter()
        self._concurrent_tasks = 0
        self._pending_tasks = 0
        self._api_calls = 0
        self._retry_count = 0
        self._throttling_count = 0
        self._api_latency_total = 0.0
        self._api_errors_count = 0
        self._partial_failures = 0

    async def task_started(self) -> None:
        async with self._lock:
            self._concurrent_tasks += 1

    async def task_finished(self) -> None:
        async with self._lock:
            self._concurrent_tasks = max(0, self._concurrent_tasks - 1)

    async def set_pending_tasks(self, count: int) -> None:
        async with self._lock:
            self._pending_tasks = max(0, count)

    async def record_api_call(self, latency_seconds: float) -> None:
        async with self._lock:
            self._api_calls += 1
            self._api_latency_total += latency_seconds

    async def record_retry(self, throttled: bool = False) -> None:
        async with self._lock:
            self._retry_count += 1
            if throttled:
                self._throttling_count += 1

    async def record_api_error(self) -> None:
        async with self._lock:
            self._api_errors_count += 1

    async def record_partial_failure(self) -> None:
        async with self._lock:
            self._partial_failures += 1

    async def snapshot(self) -> MetricSnapshot:
        async with self._lock:
            elapsed = max(time.perf_counter() - self._started_at, 0.0001)
            avg_latency = (
                self._api_latency_total / self._api_calls if self._api_calls else 0.0
            )
            return MetricSnapshot(
                concurrent_tasks=self._concurrent_tasks,
                pending_tasks=self._pending_tasks,
                api_calls=self._api_calls,
                api_calls_per_second=round(self._api_calls / elapsed, 4),
                retry_count=self._retry_count,
                throttling_count=self._throttling_count,
                average_api_latency=round(avg_latency, 4),
                api_errors_count=self._api_errors_count,
                partial_failures=self._partial_failures,
            )

    async def snapshots(self, interval_seconds: float) -> AsyncIterator[MetricSnapshot]:
        while True:
            await asyncio.sleep(interval_seconds)
            yield await self.snapshot()

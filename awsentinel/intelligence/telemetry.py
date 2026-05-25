import asyncio
from dataclasses import dataclass

from awsentinel.logging.config import get_logger

logger = get_logger("awsentinel.intelligence.telemetry")


@dataclass(frozen=True)
class IntelligenceMetricSnapshot:
    finding_count: int
    suppression_count: int
    graph_diff_count: int
    stale_path_count: int
    remediation_safety_outcomes: dict[str, int]
    prioritized_count: int


class IntelligenceTelemetry:
    """Async-safe deterministic counters for intelligence workflows."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._finding_count = 0
        self._suppression_count = 0
        self._graph_diff_count = 0
        self._stale_path_count = 0
        self._safety_outcomes: dict[str, int] = {}
        self._prioritized_count = 0

    async def record_findings(self, count: int) -> None:
        async with self._lock:
            self._finding_count += count

    async def record_suppressions(self, count: int) -> None:
        async with self._lock:
            self._suppression_count += count

    async def record_graph_diff(self, count: int) -> None:
        async with self._lock:
            self._graph_diff_count += count

    async def record_stale_paths(self, count: int) -> None:
        async with self._lock:
            self._stale_path_count += count

    async def record_safety_outcome(self, outcome: str) -> None:
        async with self._lock:
            self._safety_outcomes[outcome] = self._safety_outcomes.get(outcome, 0) + 1

    async def record_prioritized(self, count: int) -> None:
        async with self._lock:
            self._prioritized_count += count

    async def snapshot(self) -> IntelligenceMetricSnapshot:
        async with self._lock:
            snapshot = IntelligenceMetricSnapshot(
                finding_count=self._finding_count,
                suppression_count=self._suppression_count,
                graph_diff_count=self._graph_diff_count,
                stale_path_count=self._stale_path_count,
                remediation_safety_outcomes=dict(sorted(self._safety_outcomes.items())),
                prioritized_count=self._prioritized_count,
            )
        logger.info("intelligence_metrics_snapshot", **snapshot.__dict__)
        return snapshot

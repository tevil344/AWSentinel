import hashlib
from datetime import datetime
from typing import Iterable

from awsentinel.findings.models import RiskFinding
from awsentinel.intelligence.models import SuppressionRecord


def finding_hash(finding: RiskFinding) -> str:
    stable = (
        f"{finding.finding_type}:"
        f"{finding.principal}:"
        f"{finding.target}:"
        f"{finding.matched_privesc_path}"
    )
    return hashlib.sha256(stable.encode()).hexdigest()


class SuppressionEngine:
    """Deterministic suppression matcher with expiration handling."""

    def filter_active(
        self,
        findings: Iterable[RiskFinding],
        suppressions: Iterable[SuppressionRecord],
        now: datetime,
    ) -> tuple[RiskFinding, ...]:
        active_hashes = {
            suppression.finding_hash
            for suppression in suppressions
            if not suppression.is_expired(now)
        }
        return tuple(
            finding
            for finding in sorted(findings, key=lambda item: item.finding_id)
            if finding_hash(finding) not in active_hashes
        )

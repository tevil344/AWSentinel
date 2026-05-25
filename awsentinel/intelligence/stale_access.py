from datetime import datetime, timezone
from typing import Iterable, Optional

from awsentinel.intelligence.constants import DEFAULT_INACTIVITY_DAYS
from awsentinel.intelligence.models import StaleAccessFinding


class StaleAccessAnalyzer:
    """Identifies dormant identities, access keys, permissions, and paths."""

    def analyze(
        self,
        principals: Iterable[str],
        last_seen_by_principal: dict[str, Optional[datetime]],
        threshold_days: int = DEFAULT_INACTIVITY_DAYS,
    ) -> tuple[StaleAccessFinding, ...]:
        findings: list[StaleAccessFinding] = []
        now = datetime.now(timezone.utc)
        for principal in sorted(principals):
            last_seen = last_seen_by_principal.get(principal)
            inactive_days = (
                (now - _aware(last_seen)).days if last_seen else threshold_days + 1
            )
            if inactive_days > threshold_days:
                findings.append(
                    StaleAccessFinding(
                        principal_arn=principal,
                        stale_type="DORMANT_PRINCIPAL",
                        last_seen=last_seen,
                        inactive_days=inactive_days,
                        recommendation="Review or remove dormant access.",
                    )
                )
        return tuple(findings)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

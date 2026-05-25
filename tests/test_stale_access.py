from datetime import datetime, timedelta, timezone

from awsentinel.intelligence.stale_access import StaleAccessAnalyzer
from tests.phase4_helpers import DEV_ROLE


def test_stale_access_detects_dormant_principal():
    findings = StaleAccessAnalyzer().analyze(
        (DEV_ROLE,),
        {DEV_ROLE: datetime.now(timezone.utc) - timedelta(days=400)},
        threshold_days=90,
    )

    assert findings[0].inactive_days >= 399
    assert findings[0].stale_type == "DORMANT_PRINCIPAL"

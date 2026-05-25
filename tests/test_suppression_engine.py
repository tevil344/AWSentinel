from datetime import datetime, timedelta, timezone

from awsentinel.intelligence.models import SuppressionRecord
from awsentinel.intelligence.suppression_engine import SuppressionEngine, finding_hash
from tests.phase4_helpers import attack_fixture


def test_suppression_expiration_filters_only_active_suppressions():
    _, _, _, finding, _ = attack_fixture()
    now = datetime.now(timezone.utc)
    active = SuppressionRecord(
        suppression_id="s-1",
        finding_hash=finding_hash(finding),
        reason="accepted risk",
        created_by="test",
        expires_at=now + timedelta(days=1),
    )
    expired = SuppressionRecord(
        suppression_id="s-2",
        finding_hash=finding_hash(finding),
        reason="old",
        created_by="test",
        expires_at=now - timedelta(days=1),
    )

    assert SuppressionEngine().filter_active((finding,), (active,), now) == ()
    assert SuppressionEngine().filter_active((finding,), (expired,), now) == (finding,)

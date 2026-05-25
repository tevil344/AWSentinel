from tests.phase4_helpers import attack_fixture, cloudtrail_event
from awsentinel.intelligence.runtime_correlation import RuntimeCorrelationEngine


def test_runtime_correlation_detects_active_and_dormant_usage():
    _, permissions, _, finding, _ = attack_fixture()

    active = RuntimeCorrelationEngine().correlate(
        (finding,), (cloudtrail_event(1),), permissions
    )[0]
    dormant = RuntimeCorrelationEngine().correlate((finding,), (), permissions)[0]

    assert active.runtime_active is True
    assert active.times_used == 1
    assert active.services_used == ("ec2",)
    assert dormant.runtime_active is False
    assert dormant.dormant_path_score == 100

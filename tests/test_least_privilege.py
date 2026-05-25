from awsentinel.intelligence.least_privilege import LeastPrivilegeEngine
from tests.phase3_helpers import dev_permissions
from tests.phase4_helpers import DEV_ROLE


def test_least_privilege_detects_unused_permissions():
    finding = LeastPrivilegeEngine().analyze(
        (dev_permissions(("ec2:RunInstances", "iam:PassRole", "s3:ListBucket")),),
        (
            {
                "Username": DEV_ROLE,
                "EventName": "RunInstances",
                "EventSource": "ec2.amazonaws.com",
            },
        ),
    )[0]

    assert finding.used_actions == ("ec2:RunInstances",)
    assert "iam:PassRole" in finding.unused_actions
    assert finding.overprivileged_score == 66

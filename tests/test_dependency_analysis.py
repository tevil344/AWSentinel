from awsentinel.intelligence.dependency_analysis import DependencyAnalysisEngine
from tests.phase4_helpers import DEV_ROLE


def test_dependency_analysis_detects_fanout_and_production_roles():
    profiles = DependencyAnalysisEngine().analyze(
        (
            {
                "service": "lambda",
                "arn": "arn:aws:lambda:::function:prod",
                "Role": DEV_ROLE,
                "tags": {"Environment": "production"},
            },
            {"service": "glue", "arn": "arn:aws:glue:::job/dev", "Role": DEV_ROLE},
        )
    )

    assert profiles[0].dependency_fanout == 2
    assert profiles[0].shared_execution_role is True
    assert profiles[0].production_critical is True

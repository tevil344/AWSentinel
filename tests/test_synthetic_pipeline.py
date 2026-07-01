from awsentinel.demo.pipeline import run_pipeline
from awsentinel.demo.synthetic_environments import (
    enterprise,
    misconfigured_sandbox,
    multi_account_organization,
    small_startup,
)


def test_synthetic_pipeline_produces_verbose_benchmarks_and_explanations():
    result = run_pipeline(misconfigured_sandbox())

    assert result.metrics["node_count"] > 0
    assert result.metrics["edge_count"] > 0
    assert result.metrics["finding_count"] > 0
    assert result.metrics["explanation_count"] == result.metrics["finding_count"]
    assert result.metrics["peak_memory_bytes"] > 0
    assert any(line.startswith("[SCAN]") for line in result.stage_logs)
    assert any(line.startswith("[AI]") for line in result.stage_logs)
    assert result.payload["explanations"][0]["evidence"]["complete"] is True


def test_synthetic_environments_have_expected_shapes():
    startup = small_startup()
    large = enterprise()
    org = multi_account_organization()

    assert len(startup.users) == 5
    assert len(startup.roles) == 4
    assert len(startup.groups) == 2
    assert len(startup.policies) == 10
    assert len(large.users) == 300
    assert len(large.roles) == 150
    assert len(large.groups) == 50
    assert len(large.policies) == 700
    assert len(org) == 3
    assert len({environment.account_id for environment in org}) == 3


def test_synthetic_pipeline_is_deterministic_for_core_counts():
    first = run_pipeline(small_startup())
    second = run_pipeline(small_startup())

    assert first.metrics["node_count"] == second.metrics["node_count"]
    assert first.metrics["edge_count"] == second.metrics["edge_count"]
    assert first.metrics["finding_count"] == second.metrics["finding_count"]
    assert first.payload["findings"][0]["matched_privesc_path"] == (
        second.payload["findings"][0]["matched_privesc_path"]
    )

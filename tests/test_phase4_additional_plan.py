import asyncio
import json
from dataclasses import dataclass

from click.testing import CliRunner

from awsentinel.cli.main import main
from awsentinel.crawler.services.iam_access_advisor import get_service_last_accessed
from awsentinel.graph.risk_classifier import classify_risk
from awsentinel.graph.serializer import serialize_graph
from awsentinel.graph.types import Severity
from awsentinel.intelligence.constants import RemediationDecision
from awsentinel.intelligence.dependency_analysis import DependencyAnalysisEngine
from awsentinel.intelligence.remediation_safety import validate_remediation_safety
from tests.phase4_helpers import DEV_ROLE, attack_fixture


@dataclass(frozen=True)
class ClassifierFixture:
    privesc_to_admin: bool = True
    internet_exposed: bool = True
    environment: str = "prod"
    contains_sensitive_data: bool = False
    lateral_movement_risk: bool = True
    no_mfa_on_principal: bool = True
    active_in_kev: bool = False
    cross_account_trust: bool = False
    false_positive_prob: float = 0.9
    confidence: float = 0.95
    evidence_count: int = 2
    affected_resources: int = 150
    type: str = "ADMIN_REACHABILITY"


def test_classify_risk_formula_confidence_blast_and_remediation_mode():
    result = classify_risk(ClassifierFixture())

    assert result.risk_score == 80
    assert result.severity == Severity.CRITICAL
    assert result.blast_radius == "ACCOUNT_WIDE"
    assert result.confidence == 0.83
    assert result.auto_remediation == "APPROVAL_REQUIRED"


def test_remediation_safety_blocks_terraform_lockout_and_live_compute():
    dependencies = DependencyAnalysisEngine().analyze(
        (
            {
                "service": "lambda",
                "arn": "arn:aws:lambda:::function:prod",
                "Role": DEV_ROLE,
                "tags": {"Environment": "production"},
            },
        )
    )

    terraform = validate_remediation_safety(
        "finding-1", DEV_ROLE, dependencies, terraform_managed=True
    )
    lockout = validate_remediation_safety("finding-1", DEV_ROLE, lockout_risk=True)
    live = validate_remediation_safety("finding-1", DEV_ROLE, running_compute=True)

    assert terraform.decision == RemediationDecision.HUMAN_REVIEW
    assert terraform.reasons == ('SUGGEST_PR("IaC-managed")',)
    assert lockout.decision == RemediationDecision.BLOCKED
    assert lockout.reasons == ('BLOCKED("lockout risk")',)
    assert live.decision == RemediationDecision.BLOCKED
    assert live.reasons == ('BLOCKED("live workload")',)


def test_report_outputs_terminal_json_markdown_and_d3_graph(tmp_path):
    graph, _, _, finding, chain = attack_fixture()
    payload = serialize_graph(graph, findings=(finding,), attack_chains=(chain,))
    payload_path = tmp_path / "report.json"
    payload_path.write_text(json.dumps(payload))
    runner = CliRunner()

    terminal = runner.invoke(main, ["report", "--input", str(payload_path)])
    json_report = runner.invoke(
        main, ["report", "--format", "json", "--input", str(payload_path)]
    )
    markdown = runner.invoke(
        main, ["report", "--format", "md", "--input", str(payload_path)]
    )
    graph_report = runner.invoke(
        main, ["report", "--format", "graph", "--input", str(payload_path)]
    )

    assert terminal.exit_code == 0
    assert "[CRITICAL] ADMIN_REACHABILITY" in terminal.output
    assert "--PassRole+RunInstances-->" in terminal.output
    assert json.loads(json_report.output)["findings"][0]["risk_score"] == 90
    assert "# AWSentinel Report" in markdown.output
    d3 = json.loads(graph_report.output)
    assert sorted(d3) == ["links", "nodes"]
    assert d3["links"][0]["source"]


def test_access_advisor_generates_and_fetches_service_last_accessed_details():
    class Client:
        async def generate_service_last_accessed_details(self, **kwargs):
            assert kwargs["Arn"] == DEV_ROLE
            return {"JobId": "job-1"}

        async def get_service_last_accessed_details(self, **kwargs):
            assert kwargs["JobId"] == "job-1"
            return {
                "JobStatus": "COMPLETED",
                "ServicesLastAccessed": [{"ServiceNamespace": "iam"}],
            }

    result = asyncio.run(
        get_service_last_accessed(
            Client(),
            DEV_ROLE,
            asyncio.Semaphore(1),
            poll_delay_seconds=0.0,
        )
    )

    assert result["ServicesLastAccessed"][0]["ServiceNamespace"] == "iam"

from awsentinel.graph.privesc_engine import PrivEscEngine
from awsentinel.graph.types import EdgeType, Severity
from tests.phase3_helpers import admin_permissions, base_graph, dev_permissions


def test_passrole_runinstances_privesc_detection():
    graph = base_graph(
        (
            dev_permissions(("iam:PassRole", "ec2:RunInstances")),
            admin_permissions(),
        )
    )

    edges = PrivEscEngine().generate_edges(
        graph,
        (
            dev_permissions(("iam:PassRole", "ec2:RunInstances")),
            admin_permissions(),
        ),
    )

    assert edges[0].edge_type == EdgeType.PRIVESC_TO
    assert edges[0].path_name == "PassRole+RunInstances"
    assert edges[0].severity == Severity.CRITICAL
    assert graph.has_edge(
        "arn:aws:iam::123456789012:role/dev-deployer",
        "arn:aws:iam::123456789012:role/AdminRole",
    )


def test_explicit_deny_scp_or_boundary_restricted_permissions_do_not_escalate():
    graph = base_graph((dev_permissions(("iam:PassRole",)), admin_permissions()))

    edges = PrivEscEngine().generate_edges(
        graph, (dev_permissions(("iam:PassRole",)), admin_permissions())
    )

    assert edges == ()

from awsentinel.graph.edge_resolvers import add_edge_dedup, build_edge
from awsentinel.graph.lateral_engine import LateralMovementEngine
from awsentinel.graph.types import EdgeType
from tests.phase3_helpers import admin_permissions, base_graph, dev_permissions


def test_lateral_movement_dfs_has_cycle_protection():
    graph = base_graph(
        (
            dev_permissions(("iam:PassRole", "ec2:RunInstances")),
            admin_permissions(),
        )
    )
    add_edge_dedup(
        graph,
        build_edge(
            EdgeType.CAN_ASSUME,
            "arn:aws:iam::123456789012:role/AdminRole",
            "arn:aws:iam::123456789012:role/dev-deployer",
        ),
    )

    edges = LateralMovementEngine().generate_edges(graph, max_depth=5)

    assert edges
    assert len({edge.edge_id for edge in edges}) == len(edges)

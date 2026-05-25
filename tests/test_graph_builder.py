from awsentinel.graph.types import EdgeType, NodeType
from tests.phase3_helpers import admin_permissions, base_graph, user_permissions


def test_graph_builder_creates_nodes_edges_and_deduplicates():
    graph = base_graph((user_permissions(("sts:AssumeRole",)), admin_permissions()))

    assert (
        graph.nodes["arn:aws:iam::123456789012:user/Alice"]["node_type"]
        == NodeType.USER.value
    )
    assert graph.nodes["arn:aws:iam::123456789012:role/AdminRole"]["is_admin"] is True
    edge_types = {data["edge_type"] for _, _, data in graph.edges(data=True)}
    assert EdgeType.CAN_ASSUME.value in edge_types
    assert EdgeType.INSTANCE_PROFILE.value in edge_types

    initial_edges = graph.number_of_edges()
    graph.add_edge(
        "arn:aws:iam::123456789012:user/Alice",
        "arn:aws:iam::123456789012:role/AdminRole",
        edge_id="duplicate",
    )
    assert graph.number_of_edges() == initial_edges

from awsentinel.graph.bfs_engine import AttackPathEngine
from awsentinel.graph.privesc_engine import PrivEscEngine
from tests.phase3_helpers import admin_permissions, base_graph, dev_permissions


def test_bfs_shortest_and_all_paths_find_admin_reachability():
    permissions = (
        dev_permissions(("iam:PassRole", "ec2:RunInstances")),
        admin_permissions(),
    )
    graph = base_graph(permissions)
    PrivEscEngine().generate_edges(graph, permissions)

    engine = AttackPathEngine()
    shortest = engine.shortest_paths_to_admin(graph)
    all_paths = engine.all_paths_to_admin(graph)

    assert any(path.target.endswith(":role/AdminRole") for path in shortest)
    assert any(path.path_length == 1 for path in shortest)
    assert len(all_paths) >= len(shortest)

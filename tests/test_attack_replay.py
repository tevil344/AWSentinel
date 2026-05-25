from awsentinel.graph.attack_replay import build_attack_chain
from awsentinel.graph.bfs_engine import AttackPathEngine
from awsentinel.graph.privesc_engine import PrivEscEngine
from tests.phase3_helpers import admin_permissions, base_graph, dev_permissions


def test_attack_replay_generation_is_deterministic_and_serializable():
    permissions = (
        dev_permissions(("iam:PassRole", "ec2:RunInstances")),
        admin_permissions(),
    )
    graph = base_graph(permissions)
    PrivEscEngine().generate_edges(graph, permissions)
    attack_path = AttackPathEngine().shortest_paths_to_admin(graph)[0]

    chain = build_attack_chain(graph, attack_path)

    assert chain.chain_id.endswith(":1")
    assert chain.steps[0].required_permissions == ("ec2:RunInstances", "iam:PassRole")
    assert chain.to_dict()["steps"][0]["path_type"] == "PRIVESC_TO"

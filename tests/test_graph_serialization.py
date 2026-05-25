from awsentinel.findings.generator import FindingGenerator
from awsentinel.graph.attack_replay import build_attack_chain
from awsentinel.graph.bfs_engine import AttackPathEngine
from awsentinel.graph.privesc_engine import PrivEscEngine
from awsentinel.graph.serializer import serialize_graph
from tests.phase3_helpers import admin_permissions, base_graph, dev_permissions


def test_graph_serialization_preserves_findings_and_replay_chains():
    permissions = (
        dev_permissions(("iam:PassRole", "ec2:RunInstances")),
        admin_permissions(),
    )
    graph = base_graph(permissions)
    PrivEscEngine().generate_edges(graph, permissions)
    attack_path = AttackPathEngine().shortest_paths_to_admin(graph)[0]
    chain = build_attack_chain(graph, attack_path)
    finding = FindingGenerator().from_attack_paths(graph, (attack_path,))[0]

    payload = serialize_graph(graph, findings=(finding,), attack_chains=(chain,))

    assert sorted(payload) == ["attack_chains", "edges", "findings", "nodes"]
    assert payload["findings"][0]["severity"] == "CRITICAL"
    assert (
        payload["attack_chains"][0]["steps"][0]["action_taken"]
        == "PassRole+RunInstances"
    )

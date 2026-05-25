from awsentinel.graph.serializer import serialize_graph
from awsentinel.intelligence.graph_diff import GraphDiffEngine
from tests.phase4_helpers import attack_fixture


def test_graph_diff_detects_new_attack_paths():
    graph, _, _, finding, chain = attack_fixture()
    previous = {"nodes": [], "edges": [], "findings": [], "attack_chains": []}
    current = serialize_graph(graph, findings=(finding,), attack_chains=(chain,))

    diff = GraphDiffEngine().diff(previous, current)

    assert len(diff.new_paths) == 1
    assert diff.risk_delta == 1
    assert diff.newly_reachable_admins == ("arn:aws:iam::123456789012:role/AdminRole",)

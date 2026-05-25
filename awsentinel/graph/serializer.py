from typing import Iterable


def serialize_graph(
    graph, findings: Iterable = (), attack_chains: Iterable = ()
) -> dict:
    nodes = [
        dict(data)
        for _, data in sorted(graph.nodes(data=True), key=lambda item: item[0])
    ]
    edges = [
        dict(data)
        for _, _, data in sorted(
            graph.edges(data=True),
            key=lambda item: (
                item[2].get("source"),
                item[2].get("target"),
                item[2].get("edge_id"),
            ),
        )
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "findings": [
            finding.to_dict() if hasattr(finding, "to_dict") else finding
            for finding in sorted(findings, key=lambda item: item.finding_id)
        ],
        "attack_chains": [
            chain.to_dict() if hasattr(chain, "to_dict") else chain
            for chain in sorted(attack_chains, key=lambda item: item.chain_id)
        ],
    }

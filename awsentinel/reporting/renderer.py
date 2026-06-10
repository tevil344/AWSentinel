import json
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "bright_red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "blue",
}


def load_report_payload(path: str | Path) -> dict[str, Any]:
    with Path(path).expanduser().open() as handle:
        payload = json.load(handle)
    return normalize_report_payload(payload)


def normalize_report_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "findings": list(payload.get("findings", [])),
        "attack_chains": list(payload.get("attack_chains", [])),
        "nodes": list(payload.get("nodes", payload.get("graph", {}).get("nodes", []))),
        "edges": list(payload.get("edges", payload.get("graph", {}).get("edges", []))),
    }


def sorted_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        payload.get("findings", []),
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get("severity", "LOW")), 99),
            -int(item.get("risk_score", 0)),
            str(item.get("id") or item.get("finding_id", "")),
        ),
    )


def terminal_report(payload: dict[str, Any]) -> list[tuple[str, str]]:
    chains = _chains_by_finding(payload)
    lines: list[tuple[str, str]] = []
    for finding in sorted_findings(payload):
        severity = str(finding.get("severity", "LOW"))
        color = SEVERITY_COLORS.get(severity, "white")
        finding_id = finding.get("id") or finding.get("finding_id")
        finding_type = finding.get("type") or finding.get("finding_type")
        lines.append(
            (
                color,
                (
                    f"[{severity}] {finding_type} {finding_id} "
                    f"score={finding.get('risk_score', 0)} "
                    f"confidence={finding.get('confidence', 0)} "
                    f"blast={finding.get('blast_radius', 'SMALL')} "
                    f"remediation={finding.get('auto_remediation', 'SUGGEST_ONLY')}"
                ),
            )
        )
        chain = chains.get(str(finding_id))
        if chain:
            for step in chain.get("steps", []):
                lines.append(
                    (
                        "white",
                        (
                            "  -> "
                            f"{step.get('source_node')} "
                            f"--{step.get('action_taken')}--> "
                            f"{step.get('target_node')}"
                        ),
                    )
                )
        elif finding.get("attack_path", {}).get("nodes"):
            lines.append(
                ("white", "  -> " + " -> ".join(finding["attack_path"]["nodes"]))
            )
    return lines


def markdown_report(payload: dict[str, Any]) -> str:
    lines = ["# AWSentinel Report", ""]
    chains = _chains_by_finding(payload)
    for finding in sorted_findings(payload):
        finding_id = finding.get("id") or finding.get("finding_id")
        lines.extend(
            [
                f"## {finding.get('severity', 'LOW')} - {finding.get('type') or finding.get('finding_type')}",
                "",
                f"- ID: `{finding_id}`",
                f"- Risk score: `{finding.get('risk_score', 0)}`",
                f"- Confidence: `{finding.get('confidence', 0)}`",
                f"- Blast radius: `{finding.get('blast_radius', 'SMALL')}`",
                f"- Auto remediation: `{finding.get('auto_remediation', 'SUGGEST_ONLY')}`",
                "",
            ]
        )
        chain = chains.get(str(finding_id))
        if chain:
            lines.append("Attack path:")
            for step in chain.get("steps", []):
                lines.append(
                    "- "
                    f"`{step.get('source_node')}` "
                    f"--{step.get('action_taken')}--> "
                    f"`{step.get('target_node')}`"
                )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def d3_graph_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_report_payload(payload)
    nodes = []
    for node in normalized["nodes"]:
        node_id = node.get("node_id") or node.get("id") or node.get("arn")
        nodes.append(
            {
                "id": node_id,
                "label": node.get("arn") or node_id,
                "type": node.get("node_type", "UNKNOWN"),
                "severity": node.get("severity", "LOW"),
                "risk_score": node.get("risk_score", 0),
                "blast_radius": node.get("blast_radius", "SMALL"),
            }
        )
    links = []
    for edge in normalized["edges"]:
        links.append(
            {
                "source": edge.get("source"),
                "target": edge.get("target"),
                "type": edge.get("edge_type", "UNKNOWN"),
                "confidence": edge.get("confidence", 1.0),
                "severity": edge.get("severity", "LOW"),
            }
        )
    return {"nodes": nodes, "links": links}


def _chains_by_finding(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    chains = {}
    for chain in payload.get("attack_chains", []):
        chain_id = str(chain.get("chain_id", ""))
        finding_id = chain.get("finding_id")
        if finding_id:
            chains[str(finding_id)] = chain
        elif chain_id.startswith("chain:"):
            path_part = chain_id.removeprefix("chain:").rsplit(":", 1)[0]
            chains[f"finding:{path_part}"] = chain
    return chains

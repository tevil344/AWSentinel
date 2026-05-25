from datetime import datetime, timedelta, timezone

from awsentinel.findings.generator import FindingGenerator
from awsentinel.graph.attack_replay import build_attack_chain
from awsentinel.graph.bfs_engine import AttackPathEngine
from awsentinel.graph.privesc_engine import PrivEscEngine
from tests.phase3_helpers import admin_permissions, base_graph, dev_permissions

DEV_ROLE = "arn:aws:iam::123456789012:role/dev-deployer"
ADMIN_ROLE = "arn:aws:iam::123456789012:role/AdminRole"


def attack_fixture():
    permissions = (
        dev_permissions(("iam:PassRole", "ec2:RunInstances")),
        admin_permissions(),
    )
    graph = base_graph(permissions)
    PrivEscEngine().generate_edges(graph, permissions)
    path = AttackPathEngine().shortest_paths_to_admin(graph)[0]
    finding = FindingGenerator().from_attack_paths(graph, (path,))[0]
    chain = build_attack_chain(graph, path)
    return graph, permissions, path, finding, chain


def cloudtrail_event(days_ago: int, event_name: str = "RunInstances"):
    return {
        "EventName": event_name,
        "EventSource": "ec2.amazonaws.com",
        "Username": DEV_ROLE,
        "EventTime": datetime.now(timezone.utc) - timedelta(days=days_ago),
    }

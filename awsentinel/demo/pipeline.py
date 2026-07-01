import time
import tracemalloc
from dataclasses import dataclass, field
from typing import Callable

from awsentinel.demo.synthetic_environments import SyntheticEnvironment
from awsentinel.explain.engine import ExplanationEngine
from awsentinel.findings.generator import FindingGenerator
from awsentinel.graph.attack_replay import build_attack_chain
from awsentinel.graph.bfs_engine import AttackPathEngine
from awsentinel.graph.graph_builder import AuthorizationGraphBuilder
from awsentinel.graph.lateral_engine import LateralMovementEngine
from awsentinel.graph.privesc_engine import PrivEscEngine
from awsentinel.graph.serializer import serialize_graph


@dataclass(frozen=True)
class PipelineResult:
    environment_name: str
    stage_logs: tuple[str, ...]
    timings: dict[str, float]
    metrics: dict[str, int | float]
    payload: dict


@dataclass
class _PipelineState:
    logs: list[str] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)


def run_pipeline(
    environment: SyntheticEnvironment, verbose: bool = True
) -> PipelineResult:
    state = _PipelineState()
    tracemalloc.start()

    graph = _timed(
        state,
        "GRAPH",
        lambda: AuthorizationGraphBuilder().build(
            users=environment.users,
            roles=environment.roles,
            groups=environment.groups,
            managed_policies=environment.policies,
            effective_permissions=environment.effective_permissions,
            account_id=environment.account_id,
            instance_profiles=environment.instance_profiles,
        ),
        f"Built graph for {environment.name}",
    )
    privesc_edges = _timed(
        state,
        "PRIVESC",
        lambda: PrivEscEngine().generate_edges(
            graph, environment.effective_permissions
        ),
        "Matched privilege escalation paths",
    )
    lateral_edges = _timed(
        state,
        "LATERAL",
        lambda: LateralMovementEngine().generate_edges(graph),
        "DFS lateral movement completed",
    )
    attack_paths = _timed(
        state,
        "BFS",
        lambda: AttackPathEngine().shortest_paths_to_admin(graph),
        "Computed admin reachability",
    )
    chains = tuple(build_attack_chain(graph, path) for path in attack_paths)
    findings = FindingGenerator().from_attack_paths(graph, attack_paths)
    explanations = _timed(
        state,
        "AI",
        lambda: tuple(
            ExplanationEngine().generate_explanation(
                finding, _chain_for_finding(finding, chains)
            )
            for finding in findings
        ),
        "Generated deterministic explanations",
    )
    payload = _timed(
        state,
        "REPORT",
        lambda: serialize_graph(graph, findings=findings, attack_chains=chains),
        "Serialized graph report",
    )
    current_memory, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    metrics = {
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "attack_chain_count": len(chains),
        "finding_count": len(findings),
        "explanation_count": len(explanations),
        "privesc_edge_count": len(privesc_edges),
        "lateral_edge_count": len(lateral_edges),
        "current_memory_bytes": current_memory,
        "peak_memory_bytes": peak_memory,
    }
    if verbose:
        state.logs.extend(_summary_logs(environment, metrics))
    return PipelineResult(
        environment_name=environment.name,
        stage_logs=tuple(state.logs),
        timings=state.timings,
        metrics=metrics,
        payload={**payload, "explanations": [item.to_dict() for item in explanations]},
    )


def _timed(
    state: _PipelineState,
    stage: str,
    func: Callable,
    message: str,
):
    started = time.perf_counter()
    result = func()
    elapsed = round(time.perf_counter() - started, 4)
    state.timings[stage.lower()] = elapsed
    state.logs.append(f"[{stage}] ok {message} ({elapsed}s)")
    return result


def _chain_for_finding(finding, chains):
    for chain in chains:
        if chain.source == finding.principal and chain.target == finding.target:
            return chain
    return None


def _summary_logs(
    environment: SyntheticEnvironment, metrics: dict[str, int | float]
) -> tuple[str, ...]:
    return (
        f"[SCAN] ok Loaded {len(environment.users)} IAM users",
        f"[SCAN] ok Loaded {len(environment.roles)} IAM roles",
        f"[AUTHORIZATION] ok Loaded {len(environment.effective_permissions)} effective permission sets",
        f"[GRAPH] ok Built {metrics['node_count']} nodes",
        f"[GRAPH] ok Built {metrics['edge_count']} edges",
        f"[PRIVESC] ok Matched {metrics['privesc_edge_count']} privilege escalation paths",
        f"[LATERAL] ok Reachable lateral edges: {metrics['lateral_edge_count']}",
        f"[BFS] ok Admin attack paths found: {metrics['attack_chain_count']}",
        f"[AI] ok Generated {metrics['explanation_count']} explanations",
        f"[REPORT] ok Findings generated: {metrics['finding_count']}",
        f"[BENCHMARK] ok Peak memory bytes: {metrics['peak_memory_bytes']}",
    )

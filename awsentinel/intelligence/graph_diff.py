from awsentinel.intelligence.models import GraphDiffResult


class GraphDiffEngine:
    """Compares serialized graph snapshots using stable path hashes."""

    def diff(self, previous: dict, current: dict) -> GraphDiffResult:
        previous_paths = _path_hashes(previous)
        current_paths = _path_hashes(current)
        new_paths = tuple(sorted(current_paths - previous_paths))
        removed_paths = tuple(sorted(previous_paths - current_paths))
        previous_admins = _admin_targets(previous)
        current_admins = _admin_targets(current)
        return GraphDiffResult(
            new_paths=new_paths,
            removed_paths=removed_paths,
            risk_delta=len(new_paths) - len(removed_paths),
            newly_reachable_admins=tuple(sorted(current_admins - previous_admins)),
            removed_admin_paths=tuple(sorted(previous_admins - current_admins)),
        )


def _path_hashes(payload: dict) -> set[str]:
    paths: set[str] = set()
    for chain in payload.get("attack_chains", []):
        steps = chain.get("steps", [])
        stable = "->".join(
            (
                f"{step.get('source_node')}:"
                f"{step.get('action_taken')}:"
                f"{step.get('target_node')}"
            )
            for step in steps
        )
        if stable:
            paths.add(stable)
    return paths


def _admin_targets(payload: dict) -> set[str]:
    return {
        finding.get("target", "")
        for finding in payload.get("findings", [])
        if finding.get("finding_type") == "ADMIN_REACHABILITY"
    }

import hashlib
import json

from awsentinel.db.intelligence_models import GraphSnapshotRaw


def graph_hash(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class GraphSnapshotRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    def save(
        self,
        scan_id: str,
        graph_json: dict,
        findings_json: list[dict],
        attack_chains_json: list[dict],
    ) -> str:
        payload = {
            "graph": graph_json,
            "findings": findings_json,
            "attack_chains": attack_chains_json,
        }
        digest = graph_hash(payload)
        with self._session_factory() as session:
            session.add(
                GraphSnapshotRaw(
                    scan_id=scan_id,
                    graph_hash=digest,
                    graph_json=graph_json,
                    findings_json=findings_json,
                    attack_chains_json=attack_chains_json,
                )
            )
            session.commit()
        return digest

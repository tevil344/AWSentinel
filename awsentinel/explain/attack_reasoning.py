from awsentinel.explain.models import AttackExplanation
from awsentinel.explain.templates import template_for
from awsentinel.graph.attack_replay import AttackChain


def explain_attack(
    path_name: str | None, chain: AttackChain | None = None
) -> AttackExplanation:
    template = template_for(path_name)
    replay_steps = _steps_from_chain(chain)
    steps = replay_steps or template.attack_steps
    services = tuple(
        sorted(
            {
                action.split(":", 1)[0]
                for step in (chain.steps if chain else ())
                for action in step.required_permissions
                if ":" in action
            }
        )
    )
    return AttackExplanation(
        path_name=template.path_name,
        summary=template.summary,
        steps=tuple(steps),
        services_involved=services,
    )


def _steps_from_chain(chain: AttackChain | None) -> tuple[str, ...]:
    if not chain:
        return ()
    return tuple(
        (
            f"{step.source_node} uses {step.action_taken} to reach "
            f"{step.target_node}."
        )
        for step in chain.steps
    )

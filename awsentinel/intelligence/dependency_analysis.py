from collections import defaultdict
from typing import Any, Iterable

from awsentinel.intelligence.models import DependencyProfile

ROLE_FIELDS = {
    "lambda": "Role",
    "ecs": "taskRoleArn",
    "codebuild": "serviceRole",
    "glue": "Role",
    "states": "roleArn",
}


class DependencyAnalysisEngine:
    """Builds operational dependency profiles for IAM identities."""

    def analyze(
        self, resources: Iterable[dict[str, Any]]
    ) -> tuple[DependencyProfile, ...]:
        dependencies: dict[str, list[str]] = defaultdict(list)
        production: set[str] = set()

        for resource in resources:
            service = str(resource.get("service", "")).lower()
            role_arn = _role_arn_for_resource(resource)
            resource_id = str(resource.get("arn") or resource.get("id") or resource)
            if not role_arn:
                continue
            dependencies[role_arn].append(f"{service}:{resource_id}")
            if _is_production(resource):
                production.add(role_arn)

        profiles: list[DependencyProfile] = []
        for role_arn, deps in sorted(dependencies.items()):
            services = {dep.split(":", 1)[0] for dep in deps}
            fanout = len(deps)
            risk_score = min(100, (len(services) * 15) + (fanout * 5))
            profiles.append(
                DependencyProfile(
                    principal_arn=role_arn,
                    downstream_services_count=len(services),
                    dependency_risk_score=risk_score,
                    production_critical=role_arn in production,
                    shared_execution_role=fanout > 1,
                    dependency_fanout=fanout,
                    dependencies=tuple(sorted(deps)),
                )
            )
        return tuple(profiles)


def _role_arn_for_resource(resource: dict[str, Any]) -> str:
    service = str(resource.get("service", "")).lower()
    field = ROLE_FIELDS.get(service)
    if field and resource.get(field):
        return str(resource[field])
    if service == "ec2":
        profile = resource.get("instance_profile", {})
        roles = profile.get("Roles", [])
        if roles:
            return str(roles[0].get("Arn", ""))
    return str(resource.get("role_arn", ""))


def _is_production(resource: dict[str, Any]) -> bool:
    tags = resource.get("tags", {})
    if isinstance(tags, list):
        tags = {tag.get("Key"): tag.get("Value") for tag in tags}
    env = str(tags.get("Environment") or tags.get("env") or "").lower()
    return env in {"prod", "production"}

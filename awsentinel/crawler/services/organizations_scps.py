import json
from typing import Any, Optional

from botocore.exceptions import ClientError

from awsentinel.authz.policy_normalizer import normalize_policy_document
from awsentinel.authz.scp_evaluator import (
    AccountOrgPlacement,
    SCPEvaluator,
    ServiceControlPolicy,
)
from awsentinel.crawler.utils import paginate_aws, run_with_retry
from awsentinel.logging.config import get_logger
from awsentinel.telemetry.runtime_metrics import RuntimeMetrics

logger = get_logger("awsentinel.crawler.services.organizations_scps")

ORG_FALLBACK_ERROR_CODES = {
    "AWSOrganizationsNotInUseException",
    "AccessDeniedException",
    "AccessDenied",
}


async def crawl_organizations_scps(
    client: Any,
    account_id: str,
    semaphore: Any,
    metrics: Optional[RuntimeMetrics] = None,
) -> SCPEvaluator:
    """Builds an SCP evaluator from Organizations APIs with graceful fallback."""
    try:
        await run_with_retry(
            client.describe_organization,
            service="organizations",
            api_call="DescribeOrganization",
            metrics=metrics,
        )
        policies = await _list_service_control_policies(client, semaphore, metrics)
        root_ids = await _list_roots(client, semaphore, metrics)
        scps = await _describe_scp_documents(client, policies, metrics)
        target_map = await _targets_for_policies(client, semaphore, scps, metrics)
        placement = await _account_placement(client, account_id, metrics)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ORG_FALLBACK_ERROR_CODES:
            logger.warning(
                "organizations_scp_unavailable",
                service="organizations",
                error_code=code,
            )
            return SCPEvaluator([])
        raise

    evaluator = SCPEvaluator(
        [
            ServiceControlPolicy(
                policy_id=scp.policy_id,
                name=scp.name,
                target_accounts=target_map[scp.policy_id]["accounts"],
                target_ous=target_map[scp.policy_id]["ous"],
                statements=scp.statements,
                raw_json=scp.raw_json,
            )
            for scp in scps
        ],
        [placement],
    )
    evaluator.root_ids = root_ids
    logger.info(
        "organizations_scps_crawled",
        service="organizations",
        api_call="ListPolicies",
        policies_count=len(scps),
    )
    return evaluator


async def _list_service_control_policies(
    client: Any, semaphore: Any, metrics: Optional[RuntimeMetrics]
) -> list[dict[str, Any]]:
    policies: list[dict[str, Any]] = []
    async for page in paginate_aws(
        client,
        "list_policies",
        semaphore,
        service="organizations",
        metrics=metrics,
        Filter="SERVICE_CONTROL_POLICY",
    ):
        policies.extend(page.get("Policies", []))
    return policies


async def _list_roots(
    client: Any, semaphore: Any, metrics: Optional[RuntimeMetrics]
) -> tuple[str, ...]:
    root_ids: list[str] = []
    async for page in paginate_aws(
        client,
        "list_roots",
        semaphore,
        service="organizations",
        metrics=metrics,
    ):
        root_ids.extend(root["Id"] for root in page.get("Roots", []))
    return tuple(root_ids)


async def _describe_scp_documents(
    client: Any,
    policies: list[dict[str, Any]],
    metrics: Optional[RuntimeMetrics],
) -> list[ServiceControlPolicy]:
    scps: list[ServiceControlPolicy] = []
    for policy in policies:
        response = await run_with_retry(
            client.describe_policy,
            PolicyId=policy["Id"],
            service="organizations",
            api_call="DescribePolicy",
            metrics=metrics,
        )
        policy_detail = response["Policy"]
        content = json.loads(policy_detail["Content"])
        summary = policy_detail.get("PolicySummary", policy)
        scps.append(
            ServiceControlPolicy(
                policy_id=summary["Id"],
                name=summary["Name"],
                target_accounts=(),
                target_ous=(),
                statements=normalize_policy_document(content),
                raw_json=policy_detail,
            )
        )
    return scps


async def _targets_for_policies(
    client: Any,
    semaphore: Any,
    scps: list[ServiceControlPolicy],
    metrics: Optional[RuntimeMetrics],
) -> dict[str, dict[str, tuple[str, ...]]]:
    target_map: dict[str, dict[str, tuple[str, ...]]] = {}
    for scp in scps:
        accounts: set[str] = set()
        ous: set[str] = set()
        async for page in paginate_aws(
            client,
            "list_targets_for_policy",
            semaphore,
            service="organizations",
            metrics=metrics,
            PolicyId=scp.policy_id,
        ):
            for target in page.get("Targets", []):
                target_type = target.get("Type")
                target_id = target.get("TargetId")
                if target_type == "ACCOUNT" and target_id:
                    accounts.add(target_id)
                elif target_type == "ORGANIZATIONAL_UNIT" and target_id:
                    ous.add(target_id)
        target_map[scp.policy_id] = {
            "accounts": tuple(sorted(accounts)),
            "ous": tuple(sorted(ous)),
        }
    return target_map


async def _account_placement(
    client: Any,
    account_id: str,
    metrics: Optional[RuntimeMetrics],
) -> AccountOrgPlacement:
    ou_ids: list[str] = []
    child_id = account_id
    child_type = "ACCOUNT"

    while True:
        response = await run_with_retry(
            client.list_parents,
            ChildId=child_id,
            service="organizations",
            api_call="ListParents",
            metrics=metrics,
        )
        parents = response.get("Parents", [])
        if not parents:
            break

        parent = parents[0]
        if parent.get("Type") != "ORGANIZATIONAL_UNIT":
            break

        parent_id = parent["Id"]
        ou_ids.append(parent_id)
        child_id = parent_id
        child_type = "ORGANIZATIONAL_UNIT"

        if child_type != "ORGANIZATIONAL_UNIT":
            break

    return AccountOrgPlacement(account_id=account_id, ou_ids=tuple(ou_ids))

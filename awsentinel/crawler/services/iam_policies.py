import asyncio
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError
import logging

from awsentinel.models.policy import PolicyRecord
from awsentinel.crawler.utils import run_with_retry, paginate_aws

logger = logging.getLogger("awsentinel.crawler.services.iam_policies")


async def get_policy(
    client: Any, policy_arn: str, semaphore: asyncio.Semaphore
) -> Optional[Dict[str, Any]]:
    """Retrieves detailed metadata for a specific managed IAM policy."""
    async with semaphore:
        try:
            res = await run_with_retry(client.get_policy, PolicyArn=policy_arn)
            return res.get("Policy", {})
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ["AccessDenied", "NoSuchEntity"]:
                logger.warning(
                    f"Could not get policy details for policy {policy_arn}: {code}"
                )
                return None
            logger.error(
                f"AWS API failure: service=iam, api=get_policy, error_code={code}, resource={policy_arn}"
            )
            raise


async def get_policy_version(
    client: Any, policy_arn: str, version_id: str, semaphore: asyncio.Semaphore
) -> Optional[Dict[str, Any]]:
    """Retrieves the details and document of a specific version of a managed policy."""
    async with semaphore:
        try:
            res = await run_with_retry(
                client.get_policy_version, PolicyArn=policy_arn, VersionId=version_id
            )
            return res.get("PolicyVersion", {})
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ["AccessDenied", "NoSuchEntity"]:
                logger.warning(
                    f"Could not get policy version {version_id} for policy {policy_arn}: {code}"
                )
                return None
            logger.error(
                f"AWS API failure: service=iam, api=get_policy_version, error_code={code}, "
                f"resource={policy_arn}/version/{version_id}"
            )
            raise


async def list_policy_versions(
    client: Any, policy_arn: str, semaphore: asyncio.Semaphore
) -> List[Dict[str, Any]]:
    """Lists all versions of a specific managed policy."""
    versions = []
    try:
        async for page in paginate_aws(
            client, "list_policy_versions", semaphore, PolicyArn=policy_arn
        ):
            versions.extend(page.get("Versions", []))
    except Exception as e:
        logger.warning(f"Failed listing versions for policy {policy_arn}: {e}")
    return versions


async def list_entities_for_policy(
    client: Any, policy_arn: str, semaphore: asyncio.Semaphore
) -> Dict[str, List[Dict[str, Any]]]:
    """Lists the IAM users, roles, and groups attached to a specific policy."""
    users = []
    roles = []
    groups = []
    try:
        async for page in paginate_aws(
            client, "list_entities_for_policy", semaphore, PolicyArn=policy_arn
        ):
            users.extend(page.get("PolicyUsers", []))
            roles.extend(page.get("PolicyRoles", []))
            groups.extend(page.get("PolicyGroups", []))
    except Exception as e:
        logger.warning(f"Failed listing entities for policy {policy_arn}: {e}")

    return {
        "PolicyUsers": users,
        "PolicyRoles": roles,
        "PolicyGroups": groups,
    }


async def crawl_single_policy(
    client: Any, policy: Dict[str, Any], semaphore: asyncio.Semaphore, account_id: str
) -> PolicyRecord:
    """Crawls all sub-resources (versions, entities, and active document) for a managed policy concurrently."""
    policy_arn = policy["Arn"]
    default_version_id = policy["DefaultVersionId"]

    # Concurrent fetch of sub-resources
    policy_detail_task = get_policy(client, policy_arn, semaphore)
    versions_task = list_policy_versions(client, policy_arn, semaphore)
    entities_task = list_entities_for_policy(client, policy_arn, semaphore)
    default_version_task = get_policy_version(
        client, policy_arn, default_version_id, semaphore
    )

    policy_detail, versions, entities, default_version = await asyncio.gather(
        policy_detail_task,
        versions_task,
        entities_task,
        default_version_task,
    )

    # Extract policy document from the default version
    document = {}
    if default_version and "Document" in default_version:
        document = default_version["Document"]

    # Compile exact raw response dictionary matching AWS formats
    raw_response = {
        "Policy": policy_detail or policy,
        "Versions": versions,
        "Entities": entities,
        "DefaultVersion": default_version or {},
    }

    return PolicyRecord(
        arn=policy_arn,
        account_id=account_id,
        policy_name=policy["PolicyName"],
        policy_id=policy["PolicyId"],
        path=policy.get("Path", "/"),
        create_date=(
            policy["CreateDate"].isoformat()
            if hasattr(policy["CreateDate"], "isoformat")
            else str(policy["CreateDate"])
        ),
        default_version_id=default_version_id,
        document=document,
        versions=versions,
        entities=entities,
        metadata={"crawled_policy_name": policy["PolicyName"]},
        raw_response=raw_response,
    )


async def crawl_policies(
    client: Any, semaphore: asyncio.Semaphore, account_id: str
) -> List[PolicyRecord]:
    """Lists all Customer-Managed policies in the account and crawls their metadata concurrently."""
    policies_raw = []
    try:
        # Scope='Local' filters to Customer Managed policies.
        async for page in paginate_aws(
            client, "list_policies", semaphore, Scope="Local"
        ):
            policies_raw.extend(page.get("Policies", []))
    except Exception as e:
        logger.error(f"Failed to list policies for crawl: {e}")
        return []

    if not policies_raw:
        return []

    # Crawl each policy concurrently
    tasks = [
        crawl_single_policy(client, policy, semaphore, account_id)
        for policy in policies_raw
    ]
    return list(await asyncio.gather(*tasks))

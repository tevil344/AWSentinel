import asyncio
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError
import logging

from awsentinel.models.principal import GroupRecord
from awsentinel.crawler.utils import run_with_retry, paginate_aws
from awsentinel.telemetry.runtime_metrics import RuntimeMetrics

logger = logging.getLogger("awsentinel.crawler.services.iam_groups")


async def get_group(
    client: Any, group_name: str, semaphore: asyncio.Semaphore
) -> Dict[str, Any]:
    """Retrieves group details and the list of users belonging to the group (paginated)."""
    users = []
    group_info = {}
    try:
        async for page in paginate_aws(
            client, "get_group", semaphore, GroupName=group_name
        ):
            if not group_info and "Group" in page:
                group_info = page["Group"]
            users.extend(page.get("Users", []))
    except Exception as e:
        logger.warning(
            f"Failed to fetch group details/users for group {group_name}: {e}"
        )
    return {"Group": group_info, "Users": users}


async def list_group_policies(
    client: Any, group_name: str, semaphore: asyncio.Semaphore
) -> List[str]:
    """Lists names of inline policies attached to the group."""
    policies = []
    try:
        async for page in paginate_aws(
            client, "list_group_policies", semaphore, GroupName=group_name
        ):
            policies.extend(page.get("PolicyNames", []))
    except Exception as e:
        logger.warning(f"Failed listing inline policies for group {group_name}: {e}")
    return policies


async def get_group_policy(
    client: Any, group_name: str, policy_name: str, semaphore: asyncio.Semaphore
) -> Optional[Dict[str, Any]]:
    """Retrieves the details and document of a specific inline group policy."""
    async with semaphore:
        try:
            res = await run_with_retry(
                client.get_group_policy, GroupName=group_name, PolicyName=policy_name
            )
            return res
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ["AccessDenied", "NoSuchEntity"]:
                logger.warning(
                    f"Could not get group policy {policy_name} for group {group_name}: {code}"
                )
                return None
            logger.error(
                f"AWS API failure: service=iam, api=get_group_policy, error_code={code}, "
                f"resource={group_name}/{policy_name}"
            )
            raise


async def list_attached_group_policies(
    client: Any, group_name: str, semaphore: asyncio.Semaphore
) -> List[Dict[str, Any]]:
    """Retrieves all managed policies attached to the group."""
    policies = []
    try:
        async for page in paginate_aws(
            client, "list_attached_group_policies", semaphore, GroupName=group_name
        ):
            policies.extend(page.get("AttachedPolicies", []))
    except Exception as e:
        logger.warning(f"Failed listing attached policies for group {group_name}: {e}")
    return policies


async def crawl_single_group(
    client: Any, group: Dict[str, Any], semaphore: asyncio.Semaphore, account_id: str
) -> GroupRecord:
    """Crawls all sub-resources for a single IAM group concurrently and constructs a GroupRecord."""
    group_name = group["GroupName"]

    # Concurrent fetch of sub-resources
    group_detail_task = get_group(client, group_name, semaphore)
    inline_names_task = list_group_policies(client, group_name, semaphore)
    attached_policies_task = list_attached_group_policies(client, group_name, semaphore)

    group_detail_res, inline_names, attached_policies = await asyncio.gather(
        group_detail_task,
        inline_names_task,
        attached_policies_task,
    )

    users = group_detail_res.get("Users", [])
    group_info = group_detail_res.get("Group", group)

    # Fetch inline policy documents in parallel
    inline_policies = []
    if inline_names:
        policy_tasks = [
            get_group_policy(client, group_name, p_name, semaphore)
            for p_name in inline_names
        ]
        policy_docs = await asyncio.gather(*policy_tasks)
        inline_policies = [doc for doc in policy_docs if doc is not None]

    # Compile exact raw response dictionary matching AWS formats
    raw_response = {
        "Group": group_info,
        "Users": users,
        "InlinePolicies": inline_policies,
        "AttachedPolicies": attached_policies,
    }

    return GroupRecord(
        arn=group["Arn"],
        account_id=account_id,
        group_name=group_name,
        group_id=group["GroupId"],
        path=group.get("Path", "/"),
        create_date=(
            group["CreateDate"].isoformat()
            if hasattr(group["CreateDate"], "isoformat")
            else str(group["CreateDate"])
        ),
        users=users,
        inline_policies=inline_policies,
        attached_policies=attached_policies,
        metadata={"crawled_group_name": group_name},
        raw_response=raw_response,
    )


async def crawl_groups(
    client: Any,
    semaphore: asyncio.Semaphore,
    account_id: str,
    metrics: Optional[RuntimeMetrics] = None,
) -> List[GroupRecord]:
    """Lists all groups in the account and crawls their metadata concurrently."""
    groups_raw = []
    try:
        async for page in paginate_aws(
            client, "list_groups", semaphore, metrics=metrics
        ):
            groups_raw.extend(page.get("Groups", []))
    except Exception as e:
        logger.error(f"Failed to list groups for crawl: {e}")
        return []

    if not groups_raw:
        return []

    # Crawl each group concurrently
    tasks = [
        crawl_single_group(client, group, semaphore, account_id) for group in groups_raw
    ]
    return list(await asyncio.gather(*tasks))

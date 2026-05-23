import asyncio
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError
import logging

from awsentinel.models.principal import UserRecord
from awsentinel.crawler.utils import run_with_retry, paginate_aws

logger = logging.getLogger("awsentinel.crawler.services.iam_users")


async def get_user(
    client: Any, user_name: str, semaphore: asyncio.Semaphore
) -> Optional[Dict[str, Any]]:
    """Retrieves detailed metadata for a specific IAM user."""
    async with semaphore:
        try:
            res = await run_with_retry(client.get_user, UserName=user_name)
            return res.get("User", {})
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ["AccessDenied", "NoSuchEntity"]:
                logger.warning(
                    f"Could not get user details for user {user_name}: {code}"
                )
                return None
            logger.error(
                f"AWS API failure: service=iam, api=get_user, error_code={code}, resource={user_name}"
            )
            raise


async def list_groups_for_user(
    client: Any, user_name: str, semaphore: asyncio.Semaphore
) -> List[Dict[str, Any]]:
    """Retrieves all IAM groups a user belongs to."""
    groups = []
    try:
        async for page in paginate_aws(
            client, "list_groups_for_user", semaphore, UserName=user_name
        ):
            groups.extend(page.get("Groups", []))
    except Exception as e:
        logger.warning(f"Failed listing groups for user {user_name}: {e}")
    return groups


async def list_user_policies(
    client: Any, user_name: str, semaphore: asyncio.Semaphore
) -> List[str]:
    """Lists names of inline policies attached to the user."""
    policies = []
    try:
        async for page in paginate_aws(
            client, "list_user_policies", semaphore, UserName=user_name
        ):
            policies.extend(page.get("PolicyNames", []))
    except Exception as e:
        logger.warning(f"Failed listing inline policies for user {user_name}: {e}")
    return policies


async def get_user_policy(
    client: Any, user_name: str, policy_name: str, semaphore: asyncio.Semaphore
) -> Optional[Dict[str, Any]]:
    """Retrieves the details and document of a specific inline user policy."""
    async with semaphore:
        try:
            res = await run_with_retry(
                client.get_user_policy, UserName=user_name, PolicyName=policy_name
            )
            return res
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ["AccessDenied", "NoSuchEntity"]:
                logger.warning(
                    f"Could not get user policy {policy_name} for user {user_name}: {code}"
                )
                return None
            logger.error(
                f"AWS API failure: service=iam, api=get_user_policy, error_code={code}, "
                f"resource={user_name}/{policy_name}"
            )
            raise


async def list_attached_user_policies(
    client: Any, user_name: str, semaphore: asyncio.Semaphore
) -> List[Dict[str, Any]]:
    """Retrieves all managed policies attached to the user."""
    policies = []
    try:
        async for page in paginate_aws(
            client, "list_attached_user_policies", semaphore, UserName=user_name
        ):
            policies.extend(page.get("AttachedPolicies", []))
    except Exception as e:
        logger.warning(f"Failed listing attached policies for user {user_name}: {e}")
    return policies


async def list_access_keys(
    client: Any, user_name: str, semaphore: asyncio.Semaphore
) -> List[Dict[str, Any]]:
    """Lists the access key metadata for the user."""
    keys = []
    try:
        async for page in paginate_aws(
            client, "list_access_keys", semaphore, UserName=user_name
        ):
            keys.extend(page.get("AccessKeyMetadata", []))
    except Exception as e:
        logger.warning(f"Failed listing access keys for user {user_name}: {e}")
    return keys


async def get_access_key_last_used(
    client: Any, access_key_id: str, semaphore: asyncio.Semaphore
) -> Optional[Dict[str, Any]]:
    """Retrieves the last used datetime and service details for an access key."""
    async with semaphore:
        try:
            res = await run_with_retry(
                client.get_access_key_last_used, AccessKeyId=access_key_id
            )
            return res.get("AccessKeyLastUsed", {})
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ["AccessDenied", "NoSuchEntity"]:
                logger.warning(
                    f"Could not get access key last used status for key {access_key_id}: {code}"
                )
                return None
            logger.error(
                f"AWS API failure: service=iam, api=get_access_key_last_used, "
                f"error_code={code}, resource={access_key_id}"
            )
            raise


async def crawl_single_user(
    client: Any, user: Dict[str, Any], semaphore: asyncio.Semaphore, account_id: str
) -> UserRecord:
    """Crawls all sub-resources for a single IAM user concurrently and constructs a UserRecord."""
    user_name = user["UserName"]

    # Concurrent fetch of sub-resources
    user_detail_task = get_user(client, user_name, semaphore)
    groups_task = list_groups_for_user(client, user_name, semaphore)
    inline_names_task = list_user_policies(client, user_name, semaphore)
    attached_policies_task = list_attached_user_policies(client, user_name, semaphore)
    access_keys_task = list_access_keys(client, user_name, semaphore)

    user_detail, groups, inline_names, attached_policies, access_keys = (
        await asyncio.gather(
            user_detail_task,
            groups_task,
            inline_names_task,
            attached_policies_task,
            access_keys_task,
        )
    )

    # Fetch inline policy documents in parallel
    inline_policies = []
    if inline_names:
        policy_tasks = [
            get_user_policy(client, user_name, p_name, semaphore)
            for p_name in inline_names
        ]
        policy_docs = await asyncio.gather(*policy_tasks)
        inline_policies = [doc for doc in policy_docs if doc is not None]

    # Fetch access key last used in parallel
    access_keys_expanded = []
    if access_keys:
        key_tasks = [
            get_access_key_last_used(client, key["AccessKeyId"], semaphore)
            for key in access_keys
        ]
        last_used_results = await asyncio.gather(*key_tasks)
        for key, last_used in zip(access_keys, last_used_results):
            expanded_key = dict(key)
            if last_used:
                expanded_key["AccessKeyLastUsed"] = last_used
            access_keys_expanded.append(expanded_key)

    # Compile the raw responses payload matching the exact AWS payload
    raw_response = {
        "User": user,
        "UserDetail": user_detail or {},
        "Groups": groups,
        "InlinePolicies": inline_policies,
        "AttachedPolicies": attached_policies,
        "AccessKeys": access_keys_expanded,
    }

    return UserRecord(
        arn=user["Arn"],
        account_id=account_id,
        username=user_name,
        path=user.get("Path", "/"),
        user_id=user["UserId"],
        create_date=(
            user["CreateDate"].isoformat()
            if hasattr(user["CreateDate"], "isoformat")
            else str(user["CreateDate"])
        ),
        groups=groups,
        inline_policies=inline_policies,
        attached_policies=attached_policies,
        access_keys=access_keys_expanded,
        metadata={"crawled_user_name": user_name},
        raw_response=raw_response,
    )


async def crawl_users(
    client: Any, semaphore: asyncio.Semaphore, account_id: str
) -> List[UserRecord]:
    """Lists all users in the account and crawls their metadata and associations concurrently."""
    users_raw = []
    try:
        async for page in paginate_aws(client, "list_users", semaphore):
            users_raw.extend(page.get("Users", []))
    except Exception as e:
        logger.error(f"Failed to list users for crawl: {e}")
        return []

    if not users_raw:
        return []

    # Crawl each user concurrently
    tasks = [
        crawl_single_user(client, user, semaphore, account_id) for user in users_raw
    ]
    return list(await asyncio.gather(*tasks))

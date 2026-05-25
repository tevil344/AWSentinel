import asyncio
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError
import logging

from awsentinel.models.principal import RoleRecord
from awsentinel.crawler.services.iam_access_advisor import get_service_last_accessed
from awsentinel.crawler.utils import run_with_retry, paginate_aws
from awsentinel.telemetry.runtime_metrics import RuntimeMetrics

logger = logging.getLogger("awsentinel.crawler.services.iam_roles")


async def get_role(
    client: Any, role_name: str, semaphore: asyncio.Semaphore
) -> Optional[Dict[str, Any]]:
    """Retrieves detailed metadata for a specific IAM role."""
    async with semaphore:
        try:
            res = await run_with_retry(client.get_role, RoleName=role_name)
            return res.get("Role", {})
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ["AccessDenied", "NoSuchEntity"]:
                logger.warning(
                    f"Could not get role details for role {role_name}: {code}"
                )
                return None
            logger.error(
                f"AWS API failure: service=iam, api=get_role, error_code={code}, resource={role_name}"
            )
            raise


async def list_role_policies(
    client: Any, role_name: str, semaphore: asyncio.Semaphore
) -> List[str]:
    """Lists names of inline policies attached to the role."""
    policies = []
    try:
        async for page in paginate_aws(
            client, "list_role_policies", semaphore, RoleName=role_name
        ):
            policies.extend(page.get("PolicyNames", []))
    except Exception as e:
        logger.warning(f"Failed listing inline policies for role {role_name}: {e}")
    return policies


async def get_role_policy(
    client: Any, role_name: str, policy_name: str, semaphore: asyncio.Semaphore
) -> Optional[Dict[str, Any]]:
    """Retrieves the details and document of a specific inline role policy."""
    async with semaphore:
        try:
            res = await run_with_retry(
                client.get_role_policy, RoleName=role_name, PolicyName=policy_name
            )
            return res
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ["AccessDenied", "NoSuchEntity"]:
                logger.warning(
                    f"Could not get role policy {policy_name} for role {role_name}: {code}"
                )
                return None
            logger.error(
                f"AWS API failure: service=iam, api=get_role_policy, error_code={code}, "
                f"resource={role_name}/{policy_name}"
            )
            raise


async def list_attached_role_policies(
    client: Any, role_name: str, semaphore: asyncio.Semaphore
) -> List[Dict[str, Any]]:
    """Retrieves all managed policies attached to the role."""
    policies = []
    try:
        async for page in paginate_aws(
            client, "list_attached_role_policies", semaphore, RoleName=role_name
        ):
            policies.extend(page.get("AttachedPolicies", []))
    except Exception as e:
        logger.warning(f"Failed listing attached policies for role {role_name}: {e}")
    return policies


async def list_instance_profiles(
    client: Any, role_name: str, semaphore: asyncio.Semaphore
) -> List[Dict[str, Any]]:
    """Retrieves all instance profiles associated with the role."""
    profiles = []
    try:
        async for page in paginate_aws(
            client, "list_instance_profiles_for_role", semaphore, RoleName=role_name
        ):
            profiles.extend(page.get("InstanceProfiles", []))
    except Exception as e:
        logger.warning(f"Failed listing instance profiles for role {role_name}: {e}")
    return profiles


async def list_all_instance_profiles(
    client: Any, semaphore: asyncio.Semaphore
) -> List[Dict[str, Any]]:
    """Retrieves all IAM instance profiles in the account."""
    profiles = []
    try:
        async for page in paginate_aws(client, "list_instance_profiles", semaphore):
            profiles.extend(page.get("InstanceProfiles", []))
    except Exception as e:
        logger.warning(f"Failed listing all instance profiles: {e}")
    return profiles


async def get_instance_profile(
    client: Any, profile_name: str, semaphore: asyncio.Semaphore
) -> Optional[Dict[str, Any]]:
    """Retrieves the details of a specific instance profile."""
    async with semaphore:
        try:
            res = await run_with_retry(
                client.get_instance_profile, InstanceProfileName=profile_name
            )
            return res.get("InstanceProfile", {})
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ["AccessDenied", "NoSuchEntity"]:
                logger.warning(
                    f"Could not get instance profile details for {profile_name}: {code}"
                )
                return None
            logger.error(
                f"AWS API failure: service=iam, api=get_instance_profile, "
                f"error_code={code}, resource={profile_name}"
            )
            raise


async def list_role_tags(
    client: Any, role_name: str, semaphore: asyncio.Semaphore
) -> List[Dict[str, Any]]:
    """Retrieves tags associated with the role. Note: This API does not have a standard paginator."""
    async with semaphore:
        try:
            # We list tags. If pagination is needed, list_role_tags supports Marker, but usually tags are small.
            res = await run_with_retry(client.list_role_tags, RoleName=role_name)
            return res.get("Tags", [])
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ["AccessDenied", "NoSuchEntity"]:
                logger.warning(f"Could not list tags for role {role_name}: {code}")
                return []
            logger.error(
                f"AWS API failure: service=iam, api=list_role_tags, error_code={code}, resource={role_name}"
            )
            raise


async def crawl_single_role(
    client: Any,
    role: Dict[str, Any],
    semaphore: asyncio.Semaphore,
    account_id: str,
    metrics: Optional[RuntimeMetrics] = None,
) -> RoleRecord:
    """Crawls all sub-resources for a single IAM role concurrently and constructs a RoleRecord."""
    role_name = role["RoleName"]

    # Concurrent fetch of sub-resources
    role_detail_task = get_role(client, role_name, semaphore)
    inline_names_task = list_role_policies(client, role_name, semaphore)
    attached_policies_task = list_attached_role_policies(client, role_name, semaphore)
    instance_profiles_task = list_instance_profiles(client, role_name, semaphore)
    tags_task = list_role_tags(client, role_name, semaphore)
    service_last_accessed_task = get_service_last_accessed(
        client, role["Arn"], semaphore, metrics=metrics
    )

    (
        role_detail,
        inline_names,
        attached_policies,
        instance_profiles,
        tags,
        service_last_accessed,
    ) = await asyncio.gather(
        role_detail_task,
        inline_names_task,
        attached_policies_task,
        instance_profiles_task,
        tags_task,
        service_last_accessed_task,
    )

    # Fetch inline policy documents in parallel
    inline_policies = []
    if inline_names:
        policy_tasks = [
            get_role_policy(client, role_name, p_name, semaphore)
            for p_name in inline_names
        ]
        policy_docs = await asyncio.gather(*policy_tasks)
        inline_policies = [doc for doc in policy_docs if doc is not None]

    # Fetch detailed instance profile info in parallel
    instance_profiles_detailed = []
    if instance_profiles:
        profile_tasks = [
            get_instance_profile(client, profile["InstanceProfileName"], semaphore)
            for profile in instance_profiles
        ]
        profile_details = await asyncio.gather(*profile_tasks)
        instance_profiles_detailed = [
            prof for prof in profile_details if prof is not None
        ]

    # Compile exact raw response dictionary matching AWS formats
    raw_response = {
        "Role": role,
        "RoleDetail": role_detail or {},
        "InlinePolicies": inline_policies,
        "AttachedPolicies": attached_policies,
        "InstanceProfiles": instance_profiles_detailed,
        "Tags": tags,
        "ServiceLastAccessed": service_last_accessed,
    }

    return RoleRecord(
        arn=role["Arn"],
        account_id=account_id,
        role_name=role_name,
        role_id=role["RoleId"],
        path=role.get("Path", "/"),
        create_date=(
            role["CreateDate"].isoformat()
            if hasattr(role["CreateDate"], "isoformat")
            else str(role["CreateDate"])
        ),
        assume_role_policy_document=role.get("AssumeRolePolicyDocument", {}),
        inline_policies=inline_policies,
        attached_policies=attached_policies,
        instance_profiles=instance_profiles_detailed,
        tags=tags,
        metadata={"crawled_role_name": role_name},
        raw_response=raw_response,
    )


async def crawl_roles(
    client: Any,
    semaphore: asyncio.Semaphore,
    account_id: str,
    metrics: Optional[RuntimeMetrics] = None,
) -> List[RoleRecord]:
    """Lists all roles in the account and crawls their metadata concurrently."""
    roles_raw = []
    try:
        async for page in paginate_aws(
            client, "list_roles", semaphore, metrics=metrics
        ):
            roles_raw.extend(page.get("Roles", []))
    except Exception as e:
        logger.error(f"Failed to list roles for crawl: {e}")
        return []

    if not roles_raw:
        return []

    all_instance_profiles = await list_all_instance_profiles(client, semaphore)

    # Crawl each role concurrently
    tasks = [
        crawl_single_role(client, role, semaphore, account_id, metrics=metrics)
        for role in roles_raw
    ]
    roles = list(await asyncio.gather(*tasks))
    for role in roles:
        role.raw_response["AllInstanceProfiles"] = all_instance_profiles
    return roles

import asyncio
import os
import pytest
import aioboto3
import boto3
import unittest.mock
from unittest.mock import AsyncMock, MagicMock
from botocore.exceptions import ClientError
from moto import mock_aws

from awsentinel.crawler.credentials import AWSClientManager
from awsentinel.crawler.engine import CrawlEngine
from awsentinel.crawler.utils import run_with_retry, paginate_aws
from awsentinel.db.store import DatabaseStore
from awsentinel.db.models import UserRaw, RoleRaw, GroupRaw, PolicyRaw

# Configure pytest-asyncio loop
pytestmark = pytest.mark.asyncio


@pytest.fixture
def temp_db_path(tmp_path) -> str:
    """Fixture providing a temporary SQLite DB path."""
    return str(tmp_path / "test_db.sqlite")


async def test_successful_crawl(temp_db_path: str):
    """Verifies a successful crawl of populated IAM resources and matching SQLite persistence."""
    with mock_aws():
        # 1. Setup mock resources using synchronous boto3 (since moto is active)
        iam_client = boto3.client("iam", region_name="us-east-1")

        # Create test policies
        policy_doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
        pol_res = iam_client.create_policy(
            PolicyName="TestScanPolicy", PolicyDocument=policy_doc
        )
        policy_arn = pol_res["Policy"]["Arn"]

        # Create test group
        iam_client.create_group(GroupName="SecurityGroup")
        iam_client.attach_group_policy(GroupName="SecurityGroup", PolicyArn=policy_arn)
        iam_client.put_group_policy(
            GroupName="SecurityGroup",
            PolicyName="InlineGroupPolicy",
            PolicyDocument=policy_doc,
        )

        # Create test user
        iam_client.create_user(UserName="Alice")
        iam_client.add_user_to_group(GroupName="SecurityGroup", UserName="Alice")
        iam_client.create_access_key(UserName="Alice")
        iam_client.put_user_policy(
            UserName="Alice", PolicyName="InlineUserPolicy", PolicyDocument=policy_doc
        )

        # Create test role
        assume_role_doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
        iam_client.create_role(
            RoleName="WebRole", AssumeRolePolicyDocument=assume_role_doc
        )
        iam_client.attach_role_policy(RoleName="WebRole", PolicyArn=policy_arn)
        iam_client.put_role_policy(
            RoleName="WebRole", PolicyName="InlineRolePolicy", PolicyDocument=policy_doc
        )

        # 2. Run async crawl
        manager = AWSClientManager()
        account_id = await manager.validate_credentials()
        session = await manager.get_session()

        engine = CrawlEngine(session=session, db_path=temp_db_path)
        summary = await engine.execute_crawl(account_id)

        # 3. Assertions
        assert summary["users_count"] == 1
        assert summary["roles_count"] >= 1
        assert summary["groups_count"] == 1
        assert summary["policies_count"] == 1
        assert summary["duration_seconds"] >= 0.0

        # 4. Verify SQLite DB persistence
        store = DatabaseStore(temp_db_path)
        with store.SessionLocal() as session_db:
            # Check users_raw
            users_in_db = session_db.query(UserRaw).all()
            assert len(users_in_db) == 1
            user_row = users_in_db[0]
            assert user_row.aws_account_id == account_id
            assert user_row.resource_arn.endswith(":user/Alice")
            assert "Alice" in user_row.raw_json["User"]["UserName"]
            assert len(user_row.raw_json["Groups"]) == 1
            assert len(user_row.raw_json["InlinePolicies"]) == 1
            assert len(user_row.raw_json["AccessKeys"]) == 1

            # Check groups_raw
            groups_in_db = session_db.query(GroupRaw).all()
            assert len(groups_in_db) == 1
            group_row = groups_in_db[0]
            assert group_row.aws_account_id == account_id
            assert "SecurityGroup" in group_row.raw_json["Group"]["GroupName"]
            assert len(group_row.raw_json["Users"]) == 1

            # Check roles_raw
            roles_in_db = (
                session_db.query(RoleRaw)
                .filter(RoleRaw.resource_arn.like("%WebRole"))
                .all()
            )
            assert len(roles_in_db) == 1
            role_row = roles_in_db[0]
            assert role_row.aws_account_id == account_id
            assert (
                "InlineRolePolicy"
                in role_row.raw_json["InlinePolicies"][0]["PolicyName"]
            )

            # Check policies_raw
            policies_in_db = session_db.query(PolicyRaw).all()
            assert len(policies_in_db) == 1
            pol_row = policies_in_db[0]
            assert pol_row.aws_account_id == account_id
            assert pol_row.resource_arn == policy_arn


async def test_assume_role_flow():
    """Verifies that STS AssumeRole temporary credentials are resolved successfully."""
    with mock_aws():
        sts_client = boto3.client("sts", region_name="us-east-1")
        iam_client = boto3.client("iam", region_name="us-east-1")

        # Create role to assume
        assume_role_doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
        role_res = iam_client.create_role(
            RoleName="AWSentinelScanRole", AssumeRolePolicyDocument=assume_role_doc
        )
        role_arn = role_res["Role"]["Arn"]

        # Initialize credential resolution with target Role ARN
        manager = AWSClientManager(role_arn=role_arn)
        account_id = await manager.validate_credentials()
        session = await manager.get_session()

        # The returned account_id should be successfully retrieved and session populated
        assert account_id is not None
        assert session is not None


async def test_throttling_retry_logic():
    """Verifies the exponential backoff throttling retry handles rate limit exceptions correctly."""
    mock_func = AsyncMock()
    error_response = {"Error": {"Code": "Throttling", "Message": "Rate limit exceeded"}}

    # Simulate a throttling error first, followed by a success value
    mock_func.side_effect = [ClientError(error_response, "GetUser"), "success"]

    # Patch asyncio.sleep to run instantly
    with unittest.mock.patch("asyncio.sleep", AsyncMock()) as mock_sleep:
        result = await run_with_retry(mock_func)
        assert result == "success"
        assert mock_func.call_count == 2
        mock_sleep.assert_called_once()


async def test_missing_resource_handling(temp_db_path: str):
    """Verifies that NoSuchEntity exceptions do not terminate the crawling process."""
    with mock_aws():
        manager = AWSClientManager()
        account_id = await manager.validate_credentials()
        session = await manager.get_session()

        engine = CrawlEngine(session=session, db_path=temp_db_path)

        async with session.client("iam") as client:
            from awsentinel.crawler.services.iam_users import get_user

            res = await get_user(client, "DoesNotExistUser", engine.semaphore)
            assert res is None


async def test_graceful_access_denied_handling(temp_db_path: str):
    """Verifies that AccessDenied exceptions do not stop the scanner."""
    with mock_aws():
        manager = AWSClientManager()
        account_id = await manager.validate_credentials()
        session = await manager.get_session()

        async with session.client("iam") as client:
            # We replace client.get_user_policy with a mock that throws AccessDenied
            err_resp = {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}}
            client.get_user_policy = AsyncMock(
                side_effect=ClientError(err_resp, "GetUserPolicy")
            )

            from awsentinel.crawler.services.iam_users import get_user_policy

            res = await get_user_policy(
                client, "Alice", "InlinePolicy", asyncio.Semaphore(10)
            )
            assert res is None


async def test_pagination_handling(temp_db_path: str):
    """Verifies that standard list API operations paginate resources successfully."""
    with mock_aws():
        iam_client = boto3.client("iam", region_name="us-east-1")

        # Create multiple users to verify pagination
        for i in range(12):
            iam_client.create_user(UserName=f"User-{i}")

        manager = AWSClientManager()
        account_id = await manager.validate_credentials()
        session = await manager.get_session()

        async with session.client("iam") as client:
            semaphore = asyncio.Semaphore(10)
            users = []
            async for page in paginate_aws(client, "list_users", semaphore):
                users.extend(page.get("Users", []))

            assert len(users) >= 12

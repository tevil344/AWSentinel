import json
import sys
import types
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from botocore.exceptions import ClientError

from awsentinel.authz.action_expander import PolicySentryActionExpander
from awsentinel.authz.effective_permissions import (
    PermissionComputationEngine,
    compute_effective_permissions,
)
from awsentinel.authz.policy_normalizer import normalize_policy_document
from awsentinel.authz.scp_evaluator import (
    AccountOrgPlacement,
    SCPEvaluator,
    ServiceControlPolicy,
)
from awsentinel.crawler.services.cloudtrail_events import crawl_cloudtrail_events
from awsentinel.crawler.services.iam_access_advisor import get_service_last_accessed
from awsentinel.crawler.services.iam_roles import list_all_instance_profiles
from awsentinel.crawler.services.organizations_scps import crawl_organizations_scps
from awsentinel.crawler.utils import run_with_retry
from awsentinel.db.crawl_runs import CrawlRunCounts, CrawlRunStatus
from awsentinel.db.models import CloudTrailEventRaw, CrawlRun, UserRaw
from awsentinel.db.store import DatabaseStore
from awsentinel.logging.config import configure_logging
from awsentinel.models.authz import (
    GroupRecord,
    InlinePolicyRecord,
    ManagedPolicyRecord,
    UserRecord,
)
from awsentinel.models.principal import UserRecord as CrawledUserRecord
from awsentinel.telemetry.runtime_metrics import RuntimeMetrics

pytestmark = pytest.mark.asyncio


@pytest.fixture
def temp_db_path(tmp_path) -> str:
    return str(tmp_path / "phase2.sqlite")


def _statement_doc(effect: str, action: str | list[str]) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": effect,
            "Action": action,
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
        },
    }


async def test_policy_normalizer_expands_singletons_and_preserves_wildcards():
    statements = normalize_policy_document(_statement_doc("Allow", "s3:*"))

    assert statements[0].effect == "Allow"
    assert statements[0].actions == ("s3:*",)
    assert statements[0].resources == ("*",)
    assert statements[0].conditions == {
        "StringEquals": {"aws:RequestedRegion": "us-east-1"}
    }


async def test_effective_permission_merging_group_inheritance_and_deny_precedence():
    managed_arn = "arn:aws:iam::123456789012:policy/ReadOnly"
    group_arn = "arn:aws:iam::123456789012:group/Security"
    user_arn = "arn:aws:iam::123456789012:user/Alice"
    allow_s3 = normalize_policy_document(_statement_doc("Allow", ["s3:GetObject"]))
    deny_s3 = normalize_policy_document(_statement_doc("Deny", ["s3:Get*"]))
    allow_ec2 = normalize_policy_document(_statement_doc("Allow", ["ec2:*"]))

    user = UserRecord(
        arn=user_arn,
        account_id="123456789012",
        name="Alice",
        group_arns=(group_arn,),
        inline_policies=(
            InlinePolicyRecord(
                name="UserAllow",
                owner_arn=user_arn,
                owner_type="user",
                statements=allow_s3,
            ),
        ),
    )
    group = GroupRecord(
        arn=group_arn,
        account_id="123456789012",
        name="Security",
        inline_policies=(
            InlinePolicyRecord(
                name="GroupDeny",
                owner_arn=group_arn,
                owner_type="group",
                statements=deny_s3,
            ),
        ),
        attached_policy_arns=(managed_arn,),
    )
    managed = ManagedPolicyRecord(
        arn=managed_arn,
        account_id="123456789012",
        name="ReadOnly",
        statements=allow_ec2,
    )

    permissions = compute_effective_permissions(
        user,
        [managed],
        groups=[group],
        action_expander=_FakeActionExpander(
            {
                "s3:GetObject": ("s3:GetObject",),
                "s3:Get*": ("s3:GetObject", "s3:GetBucketAcl"),
                "ec2:*": ("ec2:DescribeInstances",),
            }
        ),
    )

    assert permissions.allowed_actions == ("ec2:DescribeInstances",)
    assert permissions.denied_actions == ("s3:GetBucketAcl", "s3:GetObject")
    assert permissions.inherited_from == (group_arn,)
    assert {policy.policy_name for policy in permissions.source_policies} == {
        "UserAllow",
        "GroupDeny",
        "ReadOnly",
    }


async def test_scp_deny_override_restricts_effective_permissions():
    user_arn = "arn:aws:iam::123456789012:user/Alice"
    user = UserRecord(
        arn=user_arn,
        account_id="123456789012",
        name="Alice",
        inline_policies=(
            InlinePolicyRecord(
                name="AllowIAM",
                owner_arn=user_arn,
                owner_type="user",
                statements=normalize_policy_document(
                    _statement_doc("Allow", ["iam:CreateUser", "s3:ListBucket"])
                ),
            ),
        ),
    )
    scp = ServiceControlPolicy(
        policy_id="p-denyiam",
        name="DenyIAM",
        target_accounts=(),
        target_ous=("ou-security",),
        statements=normalize_policy_document(_statement_doc("Deny", "iam:*")),
    )
    evaluator = SCPEvaluator(
        [scp],
        [AccountOrgPlacement(account_id="123456789012", ou_ids=("ou-security",))],
    )

    permissions = compute_effective_permissions(
        user,
        [],
        scp_evaluator=evaluator,
        action_expander=_FakeActionExpander(
            {
                "iam:*": ("iam:CreateUser", "iam:DeleteUser"),
                "iam:CreateUser": ("iam:CreateUser",),
                "s3:ListBucket": ("s3:ListBucket",),
            }
        ),
    )

    assert permissions.allowed_actions == ("s3:ListBucket",)
    assert permissions.denied_actions == ("iam:CreateUser", "iam:DeleteUser")
    assert "DenyIAM" in {policy.policy_name for policy in permissions.source_policies}


async def test_policy_sentry_expander_expands_wildcards_and_caches(monkeypatch):
    calls = []
    analysis_module = types.ModuleType("policy_sentry.analysis")
    expand_module = types.ModuleType("policy_sentry.analysis.expand")

    def fake_expand(action: str):
        calls.append(action)
        if action == "s3:*":
            return [f"s3:Action{i}" for i in range(84)]
        if action == "ec2:Get*":
            return ["ec2:GetConsoleOutput", "ec2:GetPasswordData"]
        return [action]

    expand_module.expand = fake_expand
    monkeypatch.setitem(sys.modules, "policy_sentry", types.ModuleType("policy_sentry"))
    monkeypatch.setitem(sys.modules, "policy_sentry.analysis", analysis_module)
    monkeypatch.setitem(sys.modules, "policy_sentry.analysis.expand", expand_module)

    expander = PolicySentryActionExpander()

    assert len(expander.expand_actions(("s3:*",))) == 84
    assert expander.expand_actions(("ec2:Get*",)) == (
        "ec2:GetConsoleOutput",
        "ec2:GetPasswordData",
    )
    assert len(expander.expand_actions(("s3:*",))) == 84
    assert calls.count("s3:*") == 1


async def test_permission_boundary_caps_allowed_permissions_and_policy_cache_reuses_arn():
    account_id = "123456789012"
    policy_arn = f"arn:aws:iam::{account_id}:policy/PowerUser"
    boundary_arn = f"arn:aws:iam::{account_id}:policy/Boundary"
    user_arn = f"arn:aws:iam::{account_id}:user/Alice"
    role_arn = f"arn:aws:iam::{account_id}:role/AppRole"
    managed_policy = ManagedPolicyRecord(
        arn=policy_arn,
        account_id=account_id,
        name="PowerUser",
        statements=normalize_policy_document(
            _statement_doc("Allow", ["s3:ListBucket", "ec2:StartInstances"])
        ),
    )
    boundary_policy = ManagedPolicyRecord(
        arn=boundary_arn,
        account_id=account_id,
        name="Boundary",
        statements=normalize_policy_document(_statement_doc("Allow", "s3:*")),
    )
    user = UserRecord(
        arn=user_arn,
        account_id=account_id,
        name="Alice",
        attached_policy_arns=(policy_arn,),
        permission_boundary_policy_arn=boundary_arn,
    )
    expander = _CountingActionExpander(
        {
            "s3:*": ("s3:ListBucket", "s3:GetObject"),
            "s3:ListBucket": ("s3:ListBucket",),
            "ec2:StartInstances": ("ec2:StartInstances",),
        }
    )
    engine = PermissionComputationEngine(
        [managed_policy, boundary_policy], action_expander=expander
    )

    permissions = engine.compute_effective_permissions(user)
    engine.compute_effective_permissions(
        UserRecord(
            arn=role_arn,
            account_id=account_id,
            name="Bob",
            attached_policy_arns=(policy_arn,),
        )
    )

    assert permissions.allowed_actions == ("s3:ListBucket",)
    assert expander.call_counts["s3:ListBucket"] == 1
    assert expander.call_counts["ec2:StartInstances"] == 1
    assert engine.expanded_policy_cache_size == 2


async def test_append_only_snapshots_and_crawl_run_lifecycle(temp_db_path: str):
    store = DatabaseStore(temp_db_path)
    account_id = "123456789012"
    user = CrawledUserRecord(
        arn=f"arn:aws:iam::{account_id}:user/Alice",
        account_id=account_id,
        username="Alice",
        path="/",
        user_id="AIDAEXAMPLE",
        create_date="2026-05-25T00:00:00+00:00",
        raw_response={"User": {"UserName": "Alice"}},
    )

    store.crawl_runs.start("scan-1", account_id)
    store.save_users([user], scan_id="scan-1")
    store.crawl_runs.complete(
        "scan-1",
        CrawlRunStatus.COMPLETED,
        CrawlRunCounts(users_count=1),
    )
    store.save_users([user], scan_id="scan-2")

    with store.SessionLocal() as session:
        snapshots = session.query(UserRaw).order_by(UserRaw.scan_id).all()
        crawl_run = session.query(CrawlRun).filter_by(scan_id="scan-1").one()

    assert [snapshot.scan_id for snapshot in snapshots] == ["scan-1", "scan-2"]
    assert crawl_run.status == CrawlRunStatus.COMPLETED.value
    assert crawl_run.users_count == 1
    assert crawl_run.completed_at is not None


async def test_cloudtrail_event_persistence(temp_db_path: str):
    store = DatabaseStore(temp_db_path)
    event_time = datetime.now(timezone.utc)
    events = [
        {
            "EventId": "evt-1",
            "EventTime": event_time,
            "EventName": "CreateUser",
            "Username": "arn:aws:iam::123456789012:user/Admin",
            "CloudTrailEvent": json.dumps({"eventName": "CreateUser"}),
        }
    ]

    store.save_cloudtrail_events(events, scan_id="scan-cloudtrail")

    with store.SessionLocal() as session:
        row = session.query(CloudTrailEventRaw).one()

    assert row.scan_id == "scan-cloudtrail"
    assert row.event_id == "evt-1"
    assert row.event_name == "CreateUser"
    assert row.principal_arn.endswith(":user/Admin")
    assert row.raw_json["EventName"] == "CreateUser"


async def test_cloudtrail_crawler_uses_paginated_lookup_events():
    event_time = datetime.now(timezone.utc)
    client = _FakeCloudTrailClient(
        [
            {
                "Events": [
                    {
                        "EventId": "evt-1",
                        "EventTime": event_time,
                        "EventName": "CreateRole",
                    }
                ]
            }
        ]
    )

    events = await crawl_cloudtrail_events(client, semaphore=_NoopSemaphore())

    assert events[0]["EventId"] == "evt-1"


async def test_access_advisor_collects_service_last_accessed_details():
    client = _FakeAccessAdvisorClient()

    result = await get_service_last_accessed(
        client,
        "arn:aws:iam::123456789012:user/Alice",
        semaphore=_NoopSemaphore(),
        poll_delay_seconds=0,
    )

    assert client.calls == [
        "GenerateServiceLastAccessedDetails",
        "GetServiceLastAccessedDetails",
    ]
    assert result["ServicesLastAccessed"][0]["ServiceName"] == "Amazon S3"


async def test_account_wide_instance_profile_listing_uses_list_instance_profiles():
    client = _FakeIAMInstanceProfilesClient()

    profiles = await list_all_instance_profiles(client, semaphore=_NoopSemaphore())

    assert client.calls == ["ListInstanceProfiles"]
    assert profiles[0]["InstanceProfileName"] == "AppProfile"


async def test_retry_telemetry_and_structured_logging(capsys):
    configure_logging()
    metrics = RuntimeMetrics()
    mock_func = AsyncMock()
    error_response = {"Error": {"Code": "Throttling", "Message": "Rate limit"}}
    mock_func.side_effect = [ClientError(error_response, "GetUser"), "success"]

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("asyncio.sleep", AsyncMock())
        result = await run_with_retry(
            mock_func,
            service="iam",
            api_call="get_user",
            resource_arn="arn:aws:iam::123456789012:user/Alice",
            metrics=metrics,
        )

    snapshot = await metrics.snapshot()
    captured = capsys.readouterr()

    assert result == "success"
    assert snapshot.retry_count == 1
    assert snapshot.throttling_count == 1
    assert '"event": "aws_api_throttled"' in captured.err
    assert '"api_call": "get_user"' in captured.err


async def test_organizations_scp_crawler_uses_required_api_chain():
    client = _FakeOrganizationsClient()

    evaluator = await crawl_organizations_scps(
        client, account_id="123456789012", semaphore=_NoopSemaphore()
    )

    assert client.calls == [
        "DescribeOrganization",
        "ListPolicies",
        "ListRoots",
        "DescribePolicy",
        "ListTargetsForPolicy",
        "ListParents",
        "ListParents",
    ]
    assert evaluator.root_ids == ("r-root",)
    assert evaluator.denied_actions_for_account("123456789012") == ("s3:DeleteBucket",)


async def test_organizations_access_denied_gracefully_falls_back():
    client = _AccessDeniedOrganizationsClient()

    evaluator = await crawl_organizations_scps(
        client, account_id="123456789012", semaphore=_NoopSemaphore()
    )

    assert evaluator.denied_actions_for_account("123456789012") == ()


class _FakeCloudTrailClient:
    def __init__(self, pages: list[dict]):
        self._pages = pages

    def get_paginator(self, operation_name: str):
        assert operation_name == "lookup_events"
        return _FakePaginator(self._pages)


class _FakePaginator:
    def __init__(self, pages: list[dict]):
        self._pages = pages

    def paginate(self, **kwargs):
        return _FakeAsyncPageIterator(self._pages)


class _FakeAsyncPageIterator:
    def __init__(self, pages: list[dict]):
        self._pages = pages
        self._index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._index >= len(self._pages):
            raise StopAsyncIteration
        page = self._pages[self._index]
        self._index += 1
        return page


class _NoopSemaphore:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None


class _FakeAccessAdvisorClient:
    def __init__(self):
        self.calls: list[str] = []

    async def generate_service_last_accessed_details(self, Arn: str):
        self.calls.append("GenerateServiceLastAccessedDetails")
        return {"JobId": "job-1"}

    async def get_service_last_accessed_details(self, JobId: str):
        self.calls.append("GetServiceLastAccessedDetails")
        return {
            "JobId": JobId,
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {"ServiceName": "Amazon S3", "LastAuthenticated": "2026-05-25"}
            ],
        }


class _FakeIAMInstanceProfilesClient:
    def __init__(self):
        self.calls: list[str] = []

    def get_paginator(self, operation_name: str):
        assert operation_name == "list_instance_profiles"
        self.calls.append("ListInstanceProfiles")
        return _FakePaginator(
            [
                {
                    "InstanceProfiles": [
                        {
                            "InstanceProfileName": "AppProfile",
                            "Arn": "arn:aws:iam::123456789012:instance-profile/AppProfile",
                        }
                    ]
                }
            ]
        )


class _FakeActionExpander:
    def __init__(self, expansions: dict[str, tuple[str, ...]]):
        self.expansions = expansions

    def expand_actions(self, actions: tuple[str, ...]) -> tuple[str, ...]:
        expanded = set()
        for action in actions:
            expanded.update(self.expansions.get(action, (action,)))
        return tuple(sorted(expanded))


class _CountingActionExpander(_FakeActionExpander):
    def __init__(self, expansions: dict[str, tuple[str, ...]]):
        super().__init__(expansions)
        self.call_counts: dict[str, int] = {}

    def expand_actions(self, actions: tuple[str, ...]) -> tuple[str, ...]:
        for action in actions:
            self.call_counts[action] = self.call_counts.get(action, 0) + 1
        return super().expand_actions(actions)


class _FakeOrganizationsClient:
    def __init__(self):
        self.calls: list[str] = []

    async def describe_organization(self):
        self.calls.append("DescribeOrganization")
        return {"Organization": {"Id": "o-example"}}

    def get_paginator(self, operation_name: str):
        if operation_name == "list_policies":
            self.calls.append("ListPolicies")
            return _FakePaginator(
                [
                    {
                        "Policies": [
                            {
                                "Id": "p-denys3",
                                "Name": "DenyS3Delete",
                                "Type": "SERVICE_CONTROL_POLICY",
                            }
                        ]
                    }
                ]
            )
        if operation_name == "list_roots":
            self.calls.append("ListRoots")
            return _FakePaginator([{"Roots": [{"Id": "r-root"}]}])
        if operation_name == "list_targets_for_policy":
            self.calls.append("ListTargetsForPolicy")
            return _FakePaginator(
                [
                    {
                        "Targets": [
                            {
                                "TargetId": "ou-security",
                                "Name": "Security",
                                "Type": "ORGANIZATIONAL_UNIT",
                            }
                        ]
                    }
                ]
            )
        raise AssertionError(operation_name)

    async def describe_policy(self, PolicyId: str):
        assert PolicyId == "p-denys3"
        self.calls.append("DescribePolicy")
        return {
            "Policy": {
                "PolicySummary": {
                    "Id": "p-denys3",
                    "Name": "DenyS3Delete",
                    "Type": "SERVICE_CONTROL_POLICY",
                },
                "Content": json.dumps(_statement_doc("Deny", "s3:DeleteBucket")),
            }
        }

    async def list_parents(self, ChildId: str):
        self.calls.append("ListParents")
        if ChildId == "123456789012":
            return {"Parents": [{"Id": "ou-security", "Type": "ORGANIZATIONAL_UNIT"}]}
        return {"Parents": [{"Id": "r-root", "Type": "ROOT"}]}


class _AccessDeniedOrganizationsClient:
    async def describe_organization(self):
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "DescribeOrganization",
        )

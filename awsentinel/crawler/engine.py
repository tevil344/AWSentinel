import asyncio
import time
import uuid
from typing import Dict, Any
import aioboto3

from awsentinel.db.crawl_runs import CrawlRunCounts, CrawlRunStatus
from awsentinel.db.store import DatabaseStore
from awsentinel.crawler.services.iam_users import crawl_users
from awsentinel.crawler.services.iam_roles import crawl_roles
from awsentinel.crawler.services.iam_groups import crawl_groups
from awsentinel.crawler.services.iam_policies import crawl_policies
from awsentinel.logging.config import (
    bind_scan_context,
    clear_logging_context,
    get_logger,
)
from awsentinel.telemetry.runtime_metrics import RuntimeMetrics

logger = get_logger("awsentinel.crawler.engine")


class CrawlEngine:
    """Orchestrates the concurrent asynchronous crawling of all IAM resources and their persistence in SQLite."""

    def __init__(
        self, session: aioboto3.Session, db_path: str = "~/.awsentinel/db.sqlite"
    ):
        self.session = session
        self.db_store = DatabaseStore(db_path)
        self.semaphore = asyncio.Semaphore(10)
        self.metrics = RuntimeMetrics()

    async def execute_crawl(self, account_id: str) -> Dict[str, Any]:
        """Runs the asynchronous crawls for all IAM services in parallel.

        Saves raw results to SQLite and returns the execution summary.
        """
        start_time = time.perf_counter()
        scan_id = str(uuid.uuid4())
        bind_scan_context(scan_id=scan_id, aws_account_id=account_id)
        self.db_store.crawl_runs.start(scan_id, account_id)

        logger.info("crawl_started", service="iam")

        try:
            async with self.session.client("iam") as client:
                # Fetch all resource types concurrently
                users_task = crawl_users(
                    client, self.semaphore, account_id, metrics=self.metrics
                )
                roles_task = crawl_roles(
                    client, self.semaphore, account_id, metrics=self.metrics
                )
                groups_task = crawl_groups(
                    client, self.semaphore, account_id, metrics=self.metrics
                )
                policies_task = crawl_policies(
                    client, self.semaphore, account_id, metrics=self.metrics
                )

                await self.metrics.set_pending_tasks(4)
                users, roles, groups, policies = await asyncio.gather(
                    users_task, roles_task, groups_task, policies_task
                )
                await self.metrics.set_pending_tasks(0)
        except Exception:
            snapshot = await self.metrics.snapshot()
            self.db_store.crawl_runs.complete(
                scan_id,
                CrawlRunStatus.FAILED,
                CrawlRunCounts(
                    api_errors_count=snapshot.api_errors_count,
                    throttling_events=snapshot.throttling_count,
                    partial_failures=snapshot.partial_failures,
                ),
            )
            logger.error("crawl_failed", service="iam")
            clear_logging_context()
            raise

        logger.info(
            "iam_resources_crawled",
            service="iam",
            users_count=len(users),
            roles_count=len(roles),
            groups_count=len(groups),
            policies_count=len(policies),
        )

        # Persist raw structures to the SQLite database
        self.db_store.save_users(users, scan_id=scan_id)
        self.db_store.save_roles(roles, scan_id=scan_id)
        self.db_store.save_groups(groups, scan_id=scan_id)
        self.db_store.save_policies(policies, scan_id=scan_id)

        elapsed = time.perf_counter() - start_time
        snapshot = await self.metrics.snapshot()
        status = (
            CrawlRunStatus.PARTIAL_SUCCESS
            if snapshot.partial_failures or snapshot.api_errors_count
            else CrawlRunStatus.COMPLETED
        )
        self.db_store.crawl_runs.complete(
            scan_id,
            status,
            CrawlRunCounts(
                users_count=len(users),
                roles_count=len(roles),
                groups_count=len(groups),
                policies_count=len(policies),
                api_errors_count=snapshot.api_errors_count,
                throttling_events=snapshot.throttling_count,
                partial_failures=snapshot.partial_failures,
            ),
        )
        logger.info(
            "crawl_completed",
            service="iam",
            crawl_duration=round(elapsed, 2),
            **snapshot.__dict__,
        )
        clear_logging_context()

        return {
            "scan_id": scan_id,
            "account_id": account_id,
            "users_count": len(users),
            "roles_count": len(roles),
            "groups_count": len(groups),
            "policies_count": len(policies),
            "duration_seconds": round(elapsed, 2),
        }

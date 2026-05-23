import asyncio
import time
import logging
from typing import Dict, Any
import aioboto3

from awsentinel.db.store import DatabaseStore
from awsentinel.crawler.services.iam_users import crawl_users
from awsentinel.crawler.services.iam_roles import crawl_roles
from awsentinel.crawler.services.iam_groups import crawl_groups
from awsentinel.crawler.services.iam_policies import crawl_policies

logger = logging.getLogger("awsentinel.crawler.engine")


class CrawlEngine:
    """Orchestrates the concurrent asynchronous crawling of all IAM resources and their persistence in SQLite."""

    def __init__(
        self, session: aioboto3.Session, db_path: str = "~/.awsentinel/db.sqlite"
    ):
        self.session = session
        self.db_store = DatabaseStore(db_path)
        self.semaphore = asyncio.Semaphore(10)

    async def execute_crawl(self, account_id: str) -> Dict[str, Any]:
        """Runs the asynchronous crawls for all IAM services in parallel.

        Saves raw results to SQLite and returns the execution summary.
        """
        start_time = time.perf_counter()

        logger.info(f"Initializing IAM crawler engine for account: {account_id}")

        async with self.session.client("iam") as client:
            # Fetch all resource types concurrently
            users_task = crawl_users(client, self.semaphore, account_id)
            roles_task = crawl_roles(client, self.semaphore, account_id)
            groups_task = crawl_groups(client, self.semaphore, account_id)
            policies_task = crawl_policies(client, self.semaphore, account_id)

            users, roles, groups, policies = await asyncio.gather(
                users_task, roles_task, groups_task, policies_task
            )

        logger.info(
            f"Successfully crawled: {len(users)} users, {len(roles)} roles, "
            f"{len(groups)} groups, {len(policies)} policies."
        )

        # Persist raw structures to the SQLite database
        self.db_store.save_users(users)
        self.db_store.save_roles(roles)
        self.db_store.save_groups(groups)
        self.db_store.save_policies(policies)

        elapsed = time.perf_counter() - start_time

        return {
            "account_id": account_id,
            "users_count": len(users),
            "roles_count": len(roles),
            "groups_count": len(groups),
            "policies_count": len(policies),
            "duration_seconds": round(elapsed, 2),
        }

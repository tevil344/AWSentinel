import click
import asyncio
import logging
import sys
from typing import Optional

from awsentinel.crawler.credentials import AWSClientManager
from awsentinel.crawler.engine import CrawlEngine

# Default logging configuration to stderr so it does not clutter stdout summaries
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)


@click.group()
def main() -> None:
    """AWSentinel - Open Source AWS Security Analysis Platform."""
    pass


async def _run_scan(profile: str, role_arn: str, db_path: str, verbose: bool) -> None:
    # Adjust logging verbosity if requested
    log_level = logging.INFO if verbose else logging.WARNING
    logging.getLogger("awsentinel").setLevel(log_level)

    # 1. Resolve credentials
    manager = AWSClientManager(profile=profile, role_arn=role_arn)

    # 2. Validate identity via STS
    try:
        account_id = await manager.validate_credentials()
    except Exception as e:
        click.echo(f"Fatal Credential Verification Failure: {e}", err=True)
        sys.exit(1)

    # 3. Retrieve authenticated session
    session = await manager.get_session()

    # 4. Initiate Crawler engine
    engine = CrawlEngine(session=session, db_path=db_path)

    try:
        summary = await engine.execute_crawl(account_id)
    except Exception as e:
        click.echo(f"Fatal error during account crawl execution: {e}", err=True)
        sys.exit(1)

    # 5. Output exact specified summary format
    click.echo("\nCrawl complete:")
    click.echo(f"* Account: {summary['account_id']}")
    click.echo(f"* Users: {summary['users_count']}")
    click.echo(f"* Roles: {summary['roles_count']}")
    click.echo(f"* Groups: {summary['groups_count']}")
    click.echo(f"* Policies: {summary['policies_count']}")
    click.echo(f"* Duration: {summary['duration_seconds']}s")


@main.command()
@click.option("--profile", type=str, default=None, help="AWS CLI profile name to use.")
@click.option(
    "--role-arn",
    type=str,
    default=None,
    help="AWS IAM Role ARN to assume for cross-account scans.",
)
@click.option(
    "--db-path",
    type=str,
    default="~/.awsentinel/db.sqlite",
    help="Custom SQLite DB path.",
)
@click.option("--verbose", is_flag=True, help="Enable verbose CLI crawling logs.")
def scan(
    profile: Optional[str], role_arn: Optional[str], db_path: str, verbose: bool
) -> None:
    """Inventories IAM configuration and populates SQLite database tables."""
    asyncio.run(_run_scan(profile, role_arn, db_path, verbose))


if __name__ == "__main__":
    main()

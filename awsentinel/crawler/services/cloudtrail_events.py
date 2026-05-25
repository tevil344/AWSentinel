from datetime import datetime
from typing import Any, Dict, List, Optional

from awsentinel.crawler.utils import paginate_aws
from awsentinel.logging.config import get_logger
from awsentinel.telemetry.runtime_metrics import RuntimeMetrics

logger = get_logger("awsentinel.crawler.services.cloudtrail_events")


async def crawl_cloudtrail_events(
    client: Any,
    semaphore: Any,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    lookup_attributes: Optional[List[Dict[str, str]]] = None,
    metrics: Optional[RuntimeMetrics] = None,
) -> List[Dict[str, Any]]:
    """Collects raw CloudTrail lookup events without performing analytics."""
    kwargs: dict[str, Any] = {}
    if start_time:
        kwargs["StartTime"] = start_time
    if end_time:
        kwargs["EndTime"] = end_time
    if lookup_attributes:
        kwargs["LookupAttributes"] = lookup_attributes

    events: list[dict[str, Any]] = []
    try:
        async for page in paginate_aws(
            client,
            "lookup_events",
            semaphore,
            service="cloudtrail",
            metrics=metrics,
            **kwargs,
        ):
            events.extend(page.get("Events", []))
    except Exception as exc:
        if metrics:
            await metrics.record_partial_failure()
        logger.error(
            "cloudtrail_lookup_failed",
            service="cloudtrail",
            api_call="lookup_events",
            error_code=type(exc).__name__,
        )
        raise

    logger.info(
        "cloudtrail_events_crawled",
        service="cloudtrail",
        api_call="lookup_events",
        events_count=len(events),
    )
    return events

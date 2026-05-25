import asyncio
from typing import Any, Dict, Optional

from botocore.exceptions import ClientError

from awsentinel.crawler.utils import run_with_retry
from awsentinel.logging.config import get_logger
from awsentinel.telemetry.runtime_metrics import RuntimeMetrics

logger = get_logger("awsentinel.crawler.services.iam_access_advisor")

GRACEFUL_ACCESS_ADVISOR_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "NoSuchEntity",
    "InvalidInput",
    "UnknownOperationException",
}


async def get_service_last_accessed(
    client: Any,
    arn: str,
    semaphore: asyncio.Semaphore,
    metrics: Optional[RuntimeMetrics] = None,
    max_poll_attempts: int = 5,
    poll_delay_seconds: float = 1.0,
) -> Dict[str, Any]:
    """Collects Access Advisor service-last-accessed data for an IAM entity."""
    async with semaphore:
        try:
            job_response = await run_with_retry(
                client.generate_service_last_accessed_details,
                Arn=arn,
                service="iam",
                api_call="generate_service_last_accessed_details",
                resource_arn=arn,
                metrics=metrics,
            )
        except (ClientError, NotImplementedError) as exc:
            if _should_fallback(exc):
                logger.warning(
                    "service_last_accessed_unavailable",
                    service="iam",
                    api_call="generate_service_last_accessed_details",
                    resource_arn=arn,
                    error_code=_error_code(exc),
                )
                return {}
            raise

    job_id = job_response.get("JobId")
    if not job_id:
        return {}

    for _ in range(max_poll_attempts):
        async with semaphore:
            try:
                details_response = await run_with_retry(
                    client.get_service_last_accessed_details,
                    JobId=job_id,
                    service="iam",
                    api_call="get_service_last_accessed_details",
                    resource_arn=arn,
                    metrics=metrics,
                )
            except (ClientError, NotImplementedError) as exc:
                if _should_fallback(exc):
                    logger.warning(
                        "service_last_accessed_unavailable",
                        service="iam",
                        api_call="get_service_last_accessed_details",
                        resource_arn=arn,
                        error_code=_error_code(exc),
                    )
                    return {}
                raise

        if details_response.get("JobStatus") == "COMPLETED":
            return details_response
        await asyncio.sleep(poll_delay_seconds)

    return {"JobId": job_id, "JobStatus": "IN_PROGRESS"}


def _should_fallback(exc: Exception) -> bool:
    if isinstance(exc, NotImplementedError):
        return True
    return _error_code(exc) in GRACEFUL_ACCESS_ADVISOR_CODES


def _error_code(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "")
    return type(exc).__name__

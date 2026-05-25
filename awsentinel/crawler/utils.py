import asyncio
import random
import time
from typing import Any, AsyncGenerator, Optional
from botocore.exceptions import ClientError

from awsentinel.logging.config import get_logger
from awsentinel.telemetry.runtime_metrics import RuntimeMetrics

logger = get_logger("awsentinel.crawler.utils")

THROTTLING_ERROR_CODES = {
    "Throttling",
    "RequestLimitExceeded",
    "SlowDown",
    "PriorRequestNotComplete",
}


async def run_with_retry(
    func,
    *args,
    service: str = "iam",
    api_call: Optional[str] = None,
    resource_arn: Optional[str] = None,
    metrics: Optional[RuntimeMetrics] = None,
    **kwargs,
) -> Any:
    """Executes an async callable with custom exponential backoff on AWS Throttling exceptions.

    Args:
        func: The async function to call.
        args: Positional arguments for func.
        kwargs: Keyword arguments for func.
    """
    max_retries = 5
    base_delay = 1.0  # seconds
    call_name = api_call or getattr(func, "__name__", "unknown")
    for attempt in range(max_retries):
        started = time.perf_counter()
        try:
            result = await func(*args, **kwargs)
            if metrics:
                await metrics.record_api_call(time.perf_counter() - started)
            return result
        except ClientError as e:
            if metrics:
                await metrics.record_api_error()
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in THROTTLING_ERROR_CODES:
                if metrics:
                    await metrics.record_retry(throttled=True)
                delay = (base_delay * (2**attempt)) + random.uniform(0, 0.5)
                logger.warning(
                    "aws_api_throttled",
                    service=service,
                    api_call=call_name,
                    retry_count=attempt + 1,
                    throttle_count=attempt + 1,
                    resource_arn=resource_arn,
                    error_code=error_code,
                    retry_delay_seconds=round(delay, 2),
                )
                await asyncio.sleep(delay)
            else:
                logger.error(
                    "aws_api_failure",
                    service=service,
                    api_call=call_name,
                    retry_count=attempt,
                    throttle_count=0,
                    resource_arn=resource_arn,
                    error_code=error_code,
                )
                raise
    raise RuntimeError(
        "AWS API request failed after maximum retries due to throttling."
    )


async def paginate_aws(
    client: Any,
    operation_name: str,
    semaphore: asyncio.Semaphore,
    service: str = "iam",
    metrics: Optional[RuntimeMetrics] = None,
    **kwargs: Any,
) -> AsyncGenerator[dict, None]:
    """Reusable async pagination helper that limits concurrency and handles throttling/errors gracefully.

    Yields:
        Individual pages (dictionaries) returned by the aioboto3 paginator.
    """
    async with semaphore:
        try:
            paginator = client.get_paginator(operation_name)
        except Exception as e:
            if metrics:
                await metrics.record_api_error()
            logger.error(
                "aws_paginator_create_failed",
                service=service,
                api_call=operation_name,
                retry_count=0,
                throttle_count=0,
                error_code=type(e).__name__,
            )
            return

        async_iterator = paginator.paginate(**kwargs).__aiter__()
        while True:
            try:
                page = await run_with_retry(
                    async_iterator.__anext__,
                    service=service,
                    api_call=operation_name,
                    metrics=metrics,
                )
                yield page
            except StopAsyncIteration:
                break
            except ClientError as e:
                if metrics:
                    await metrics.record_api_error()
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "AccessDenied":
                    if metrics:
                        await metrics.record_partial_failure()
                    logger.warning(
                        "aws_paginated_access_denied",
                        service=service,
                        api_call=operation_name,
                        retry_count=0,
                        throttle_count=0,
                        error_code=error_code,
                        parameters=kwargs,
                    )
                    break
                elif error_code == "NoSuchEntity":
                    if metrics:
                        await metrics.record_partial_failure()
                    logger.warning(
                        "aws_paginated_resource_missing",
                        service=service,
                        api_call=operation_name,
                        retry_count=0,
                        throttle_count=0,
                        error_code=error_code,
                        parameters=kwargs,
                    )
                    break
                else:
                    logger.error(
                        "aws_paginated_api_failure",
                        service=service,
                        api_call=operation_name,
                        retry_count=0,
                        throttle_count=0,
                        error_code=error_code,
                        parameters=kwargs,
                    )
                    raise

import asyncio
import logging
import random
from typing import Any, AsyncGenerator
from botocore.exceptions import ClientError

logger = logging.getLogger("awsentinel.crawler.utils")


async def run_with_retry(func, *args, **kwargs) -> Any:
    """Executes an async callable with custom exponential backoff on AWS Throttling exceptions.

    Args:
        func: The async function to call.
        args: Positional arguments for func.
        kwargs: Keyword arguments for func.
    """
    max_retries = 5
    base_delay = 1.0  # seconds
    for attempt in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in [
                "Throttling",
                "RequestLimitExceeded",
                "SlowDown",
                "PriorRequestNotComplete",
            ]:
                delay = (base_delay * (2**attempt)) + random.uniform(0, 0.5)
                logger.warning(
                    f"AWS API Throttled (Attempt {attempt + 1}/{max_retries}). "
                    f"Retrying in {delay:.2f}s... Error: {error_code}"
                )
                await asyncio.sleep(delay)
            else:
                # Reraise other errors (e.g. AccessDenied, NoSuchEntity) immediately
                raise
    raise RuntimeError(
        "AWS API request failed after maximum retries due to throttling."
    )


async def paginate_aws(
    client: Any, operation_name: str, semaphore: asyncio.Semaphore, **kwargs: Any
) -> AsyncGenerator[dict, None]:
    """Reusable async pagination helper that limits concurrency and handles throttling/errors gracefully.

    Yields:
        Individual pages (dictionaries) returned by the aioboto3 paginator.
    """
    async with semaphore:
        try:
            paginator = client.get_paginator(operation_name)
        except Exception as e:
            logger.error(f"Failed to create paginator for {operation_name}: {e}")
            return

        async_iterator = paginator.paginate(**kwargs).__aiter__()
        while True:
            try:
                # Wrap the asynchronous retrieval of the next page inside retry logic
                page = await run_with_retry(async_iterator.__anext__)
                yield page
            except StopAsyncIteration:
                break
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "AccessDenied":
                    logger.warning(
                        f"Access Denied during paginated operation {operation_name} "
                        f"for parameters {kwargs}: {e}"
                    )
                    break
                elif error_code == "NoSuchEntity":
                    logger.warning(
                        f"Resource not found during paginated operation {operation_name} "
                        f"for parameters {kwargs}: {e}"
                    )
                    break
                else:
                    logger.error(
                        f"AWS API failure in paginator: service=iam, api={operation_name}, "
                        f"error_code={error_code}, parameters={kwargs}"
                    )
                    raise

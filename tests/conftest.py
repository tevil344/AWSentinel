import aiobotocore.endpoint
import inspect
from typing import Any


class AioResponseProxy:
    """Proxy that ensures response attributes are awaitable as expected by aiobotocore."""

    def __init__(self, response: Any):
        self._response = response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._response, name)

    @property
    def content(self) -> Any:
        async def _get_content():
            val = self._response.content
            if inspect.isawaitable(val):
                return await val
            return val

        return _get_content()


# Store original endpoint converter
_original_convert = aiobotocore.endpoint.convert_to_response_dict


async def patched_convert(http_response: Any, operation_model: Any) -> Any:
    # Wrap response in our AioResponseProxy before passing to convert_to_response_dict
    proxy = AioResponseProxy(http_response)
    return await _original_convert(proxy, operation_model)


# Apply global compatibility patch for tests
aiobotocore.endpoint.convert_to_response_dict = patched_convert

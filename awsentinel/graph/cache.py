import asyncio
from typing import Generic, Optional, TypeVar

from cachetools import LRUCache

K = TypeVar("K")
V = TypeVar("V")


class AsyncSafeLRUCache(Generic[K, V]):
    """Small async-safe bounded cache wrapper for graph computations."""

    def __init__(self, maxsize: int = 4096) -> None:
        self._cache: LRUCache[K, V] = LRUCache(maxsize=maxsize)
        self._lock = asyncio.Lock()

    async def get(self, key: K) -> Optional[V]:
        async with self._lock:
            return self._cache.get(key)

    async def set(self, key: K, value: V) -> None:
        async with self._lock:
            self._cache[key] = value

    async def clear(self) -> None:
        async with self._lock:
            self._cache.clear()


class GraphCache:
    def __init__(self) -> None:
        self.wildcard_expansions: AsyncSafeLRUCache[str, tuple[str, ...]] = (
            AsyncSafeLRUCache()
        )
        self.trust_resolution: AsyncSafeLRUCache[str, tuple[str, ...]] = (
            AsyncSafeLRUCache()
        )
        self.managed_policy_expansions: AsyncSafeLRUCache[str, tuple[str, ...]] = (
            AsyncSafeLRUCache()
        )
        self.path_matching: AsyncSafeLRUCache[str, bool] = AsyncSafeLRUCache()

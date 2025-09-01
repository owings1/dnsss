from __future__ import annotations

from typing import Any, Callable, Mapping

__all__ = [
    'bykey',
    'byvalue',
    'dsorted',
    'dvsorted',
    'linefilter']

def bykey[T](item: tuple[T, Any]) -> T:
    return item[0]

def byvalue[T](item: tuple[Any, T]) -> T:
    return item[1]

def dsorted[K, V](mapping: Mapping[K, V], key: Callable[[tuple[K, V]], Any] = bykey, reverse: bool = False) -> dict[K, V]:
    return dict(sorted(mapping.items(), key=key, reverse=reverse))

def dvsorted[K, V](mapping: Mapping[K, V], reverse: bool = False) -> dict[K, V]:
    return dsorted(mapping, key=byvalue, reverse=reverse)

def linefilter(line: str) -> bool:
    return bool(line.strip()) and not line.startswith('#')

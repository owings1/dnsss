from __future__ import annotations

from typing import Any, Callable, Mapping, TypeVar

__all__ = [
    'bykey',
    'byvalue',
    'dsorted',
    'dvsorted',
    'linefilter']

K = TypeVar('K')
T = TypeVar('T')

def bykey(item: tuple[T, Any]) -> T:
    return item[0]

def byvalue(item: tuple[Any, T]) -> T:
    return item[1]

def dsorted(mapping: Mapping[K, T], key: Callable[[tuple[K, T]], Any] = bykey, reverse: bool = False) -> dict[K, T]:
    return dict(sorted(mapping.items(), key=key, reverse=reverse))

def dvsorted(mapping: Mapping[K, T], reverse: bool = False) -> dict[K, T]:
    return dsorted(mapping, key=byvalue, reverse=reverse)

def linefilter(line: str) -> bool:
    return bool(line.strip()) and not line.startswith('#')

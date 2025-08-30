from __future__ import annotations

from typing import Any, Mapping

__all__ = [
    'addmean',
    'byvalue',
    'dvsorted',
    'linefilter']

def addmean(value: float, mean: float, count: int) -> float:
    return (value + mean * (count - 1)) / count

def byvalue[T](item: tuple[Any, T]) -> T:
    return item[1]

def dvsorted[K, V](mapping: Mapping[K, V], reverse: bool = False) -> dict[K, V]:
    return dict(sorted(mapping.items(), key=byvalue, reverse=reverse))

def linefilter(line: str) -> bool:
    return bool(line.strip()) and not line.startswith('#')

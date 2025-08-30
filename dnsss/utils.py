from __future__ import annotations

from typing import Any

def addmean(value: float, mean: float, count: int) -> float:
    return (value + mean * (count - 1)) / count

def byvalue[T](item: tuple[Any, T]) -> T:
    return item[1]

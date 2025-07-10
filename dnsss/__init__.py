from __future__ import annotations

from typing import Any

def byvalue[T](item: tuple[Any, T]) -> T:
    return item[1]

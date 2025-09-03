from __future__ import annotations

from typing import Any, Callable, Mapping, Self, TypeVar

import tabulate
import yaml

__all__ = [
    'bykey',
    'byvalue',
    'dkpathed',
    'dsorted',
    'dvsorted',
    'linefilter',
    'tablestr']

K = TypeVar('K')
T = TypeVar('T')

def bykey(item: tuple[T, Any]) -> T:
    return item[0]

def byvalue(item: tuple[Any, T]) -> T:
    return item[1]

def dkpathed(mapping: Mapping[str, Any], path: list[str]|None = None) -> dict[str, Any]:
    path = path or []
    pathed = {}
    for key, value in mapping.items():
        kpath = path + [str(key)]
        if isinstance(value, Mapping):
            pathed.update(dkpathed(value, kpath))
        else:
            pathed['.'.join(kpath)] = value
    return pathed

def dsorted(mapping: Mapping[K, T], key: Callable[[tuple[K, T]], Any] = bykey, reverse: bool = False) -> dict[K, T]:
    return dict(sorted(mapping.items(), key=key, reverse=reverse))

def dvsorted(mapping: Mapping[K, T], reverse: bool = False) -> dict[K, T]:
    return dsorted(mapping, key=byvalue, reverse=reverse)

def linefilter(line: str) -> bool:
    return bool(line.strip()) and not line.startswith('#')

def tablestr(*args, **kw) -> LiteralStr:
    return LiteralStr(tabulate.tabulate(*args, **kw))

class LiteralStr(str):
    __slots__ = ()

    @classmethod
    def representer(cls, dumper: yaml.Dumper, data: Self) -> yaml.ScalarNode:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(LiteralStr, LiteralStr.representer)
from __future__ import annotations

from typing import Any, Callable, Mapping, Self, TypeVar

import tabulate
import yaml

from . import settings

__all__ = [
    'bykey',
    'byvalue',
    'dkpathed',
    'dsorted',
    'dvsorted',
    'LiteralStr',
    'tablestr']

K = TypeVar('K')
T = TypeVar('T')

def bykey(item: tuple[T, Any]) -> T:
    "Item key sort"
    return item[0]

def byvalue(item: tuple[Any, T]) -> T:
    "Item value sort"
    return item[1]

def dkpathed(mapping: Mapping[str, Any], *, separator: str = '.', path: list[str]|None = None) -> dict[str, Any]:
    "Flatten a mapping by recursively joining keys with separator"
    path = path or []
    pathed = {}
    for key, value in mapping.items():
        kpath = path + [key]
        if isinstance(value, Mapping):
            pathed.update(dkpathed(value, separator=separator, path=kpath))
        else:
            pathed[separator.join(kpath)] = value
    return pathed

def dsorted(mapping: Mapping[K, T], key: Callable[[tuple[K, T]], Any] = bykey, reverse: bool = False) -> dict[K, T]:
    "Return a sorted mapping"
    return dict(sorted(mapping.items(), key=key, reverse=reverse))

def dvsorted(mapping: Mapping[K, T], reverse: bool = False) -> dict[K, T]:
    "Return a sorted mapping by value"
    return dsorted(mapping, key=byvalue, reverse=reverse)

def tablestr(*args, **kw) -> LiteralStr:
    "Block literal table string for YAML"
    kw.setdefault('floatfmt', settings.YAML_FLOAT_FMT)
    return LiteralStr(tabulate.tabulate(*args, **kw))

class LiteralStr(str):
    "Force a string to be represented as a block literal by YAML"
    __slots__ = ()

    @classmethod
    def representer(cls, dumper: yaml.Dumper, data: Self) -> yaml.ScalarNode:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(LiteralStr, LiteralStr.representer)
yaml.add_representer(
    float,
    lambda dumper, data: (
        dumper.represent_float(float(f'{data:{settings.YAML_FLOAT_FMT}}'))))
from __future__ import annotations

from . import ar1, base, bind, bmod

registry: dict[str, type[base.Resolver]] = dict(
    bind=bind.Resolver,
    bmod=bmod.Resolver,
    ar1=ar1.Resolver)

__all__ = [
    'ar1',
    'bind',
    'bmod',
    'registry']
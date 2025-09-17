from __future__ import annotations

from . import ar1, base, bind, bmod

type ResolverType = base.Resolver
registry: dict[str, type[base.Resolver]] = dict(
    base=base.Resolver,
    bind=bind.Resolver,
    bmod=bmod.Resolver,
    ar1=ar1.Resolver)

__all__ = sorted([*registry, 'registry'])
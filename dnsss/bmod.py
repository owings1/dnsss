from __future__ import annotations

from typing import Any, ClassVar

from pydantic import PositiveInt

from . import addmean, byvalue
from .base import RTime, Server
from .bind import BindResolver
from .cli import BaseCommand


class BmodResolver(BindResolver):
    """
    Bind algorithm with the following optimization:
    
    When adjusting the computed R value for the server S that was just queried,
    use the maximum of:

         i. the value as computed according to the original bind algorithm
        ii. the mean observed response time of the last k queries to S

    The idea is increase the penalty for slower-responding servers, so that they
    are contacted less often, but to keep k sufficiently small to allow for
    recovery of temporary increased latency.
    """
    params: BmodResolver.Params
    kmeans: dict[Server, RTime]

    class Params(BindResolver.Params):
        k: PositiveInt = 4
        'Sample width for computing mean response time (last-k)'

    class Config(BindResolver.Config):
        params: BmodResolver.Params

    def __init__(self, config: Any) -> None:
        super().__init__(config)
        self.kmeans = dict.fromkeys(self.servers, 0.0)

    def adjust(self, S: Server, R: RTime) -> None:
        super().adjust(S, R)
        k = self.params.k
        if self.counts[S] <= k:
            self.kmeans[S] = self.means[S]
        else:
            self.kmeans[S] = addmean(R, self.kmeans[S], k)
        self.SR[S] = max(self.SR[S], self.kmeans[S])

    def state(self, *, terse: bool = False):
        return dict(
            kmeans=dict(sorted(self.kmeans.items(), key=byvalue, reverse=True)),
            **super().state())

    def load(self, state: dict[str, Any]) -> None:
        super().load(state)
        self.kmeans = state['kmeans']

class Command(BaseCommand):
    description: ClassVar = 'Bmod algorithm demo'
    resolver_class: ClassVar = BmodResolver
    slug: ClassVar = 'bmod'

if __name__ == '__main__':
    Command.main()

"""
Modified BIND algorithm with the following optimization:

When adjusting the computed R value for the server S that was just queried,
use the maximum of:

     i. The value as computed according to the original BIND algorithm
    ii. The mean observed response time of the last k queries to S

The idea is to increase the penalty for slower-responding servers, so that
they are contacted less frequently, but to keep k sufficiently small to allow
for recovery of temporary increased latency.
"""
from __future__ import annotations

from typing import Any

from ..models import *
from ..utils import *
from . import bind


class Params(bind.Params):
    k: PositiveInt = 4
    'Sample width for computing mean response time (last-k)'

class Resolver(bind.Resolver):

    class Config(bind.Resolver.Config):
        params: Params = Field(default_factory=Params)

    kmeans: dict[Server, RTime]
    config: Resolver.Config

    def __init__(self, config: Any) -> None:
        super().__init__(config)
        self.kmeans = dict.fromkeys(self.config.servers, 0.0)

    def adjust(self, S: Server, R: RTime) -> None:
        super().adjust(S, R)
        k = self.config.params.k
        if self.counts[S] <= k:
            self.kmeans[S] = self.means[S]
        else:
            self.kmeans[S] = addmean(R, self.kmeans[S], k)
        self.SR[S] = max(self.SR[S], self.kmeans[S])

    def state(self, *, terse: bool = False):
        return dict(
            kmeans=dvsorted(self.kmeans, reverse=True),
            **super().state())

    def load(self, state: dict[str, Any]) -> None:
        super().load(state)
        self.kmeans = state['kmeans']

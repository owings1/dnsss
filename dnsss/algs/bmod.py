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

from typing import Annotated

from ..models import *
from ..utils import *
from . import bind


class Params(bind.Params):
    k: PositiveInt = 4
    'Sample width for computing mean response time (last-k)'

class Config(bind.Config):
    params: Params = Field(default_factory=Params)

class State(bind.State):
    SKM: Annotated[
        dict[Server, RunningMean],
        PlainSerializer(lambda x: dvsorted(x))] = Field(default_factory=dict)

    def post_config_init(self, config: Config) -> None:
        super().post_config_init(config)
        self.SKM = {Si: RunningMean() for Si in config.servers}

class Resolver(bind.Resolver):
    config: Config
    state: State = Field(default_factory=State)

    def adjust(self, S: Server, R: NonNegativeFloat) -> None:
        super().adjust(S, R)
        KM = self.state.SKM[S]
        KM.observe(R)
        KM.count = max(KM.count, self.config.params.k)
        self.state.SR[S] = max(self.state.SR[S], KM.mean)

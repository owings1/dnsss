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

class State(bind.State):
    SKM: Annotated[
        dict[Server, RunningMean],
        PlainSerializer(dvsorted)] = Field(default_factory=dict)
    params: Params = Field(default_factory=Params, exclude=True)

    def addserver(self, S: Server) -> None:
        super().addserver(S)
        self.SKM[S] = RunningMean()

    def observe(self, S: Server, R: NonNegativeFloat, code: Rcode, servers: list[Server]) -> None:
        super().observe(S, R, code, servers)
        self.SKM[S].observe(R)
        self.SKM[S].count = max(self.SKM[S].count, self.params.k)

    def rank(self, S: Server) -> float:
        return max(super().rank(S), self.SKM[S].mean)

class Config(bind.Config):
    params: Params = Field(default_factory=Params)

class Resolver(bind.Resolver):
    config: Config = Field(default_factory=Config)
    state: State = Field(default_factory=State)

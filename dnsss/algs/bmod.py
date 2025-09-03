"""
Modified BIND algorithm with the following optimization:

Compute a value RM for each server S just like the BIND R value, except that RM
is not discounted when S is not queried.

When adjusting the computed R value for the server S that was just queried,
use the maximum of:

     i. The value as computed according to the original BIND algorithm
    ii. The value of RM

The idea is to increase the penalty for slower-responding servers, so that
they are contacted less frequently.
"""
from __future__ import annotations

from ..models import *
from . import bind


class State(bind.State):
    SRM: dict[Server, NonNegativeFloat] = Field(default_factory=dict)
    model_config = ConfigDict(sfields=['SR', 'SRM', 'SM'])

    def add(self, S: Server) -> None:
        super().add(S)
        if S not in self.SRM:
            self.SRM[S] = 0.0

    def observe(self, S: Server, R: NonNegativeFloat, code: Rcode, servers: list[Server]) -> None:
        super().observe(S, R, code, servers)
        a = self.SRM[S] and self.params.a
        self.SRM[S] = a * self.SRM[S] + (1 - a) * R
        self.SR[S] = max(self.SR[S], self.SRM[S])

class Resolver(bind.Resolver):
    state: State = Field(default_factory=State, frozen=True)

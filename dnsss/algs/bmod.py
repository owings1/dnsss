"""
(Experimental) Modified BIND algorithm with the following optimization:

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
    model_config = ConfigDict(server_dict_fields=['SRM', 'SR', 'SM'])

    def add(self, server: Server) -> None:
        super().add(server)
        if server not in self.SRM:
            self.SRM[server] = 0.0

    def observe(self, server: Server, rtime: NonNegativeFloat, code: Rcode, servers: list[Server]) -> None:
        super().observe(server, rtime, code, servers)
        a = self.SRM[server] and self.params.a
        self.SRM[server] = a * self.SRM[server] + (1 - a) * rtime
        self.SR[server] = max(self.SR[server], self.SRM[server])

class Resolver(bind.Resolver):
    state: State = Field(default_factory=State, frozen=True)

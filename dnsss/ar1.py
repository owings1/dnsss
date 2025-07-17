from __future__ import annotations

import random
from typing import Any, ClassVar

from pydantic import (NonNegativeFloat, NonNegativeInt, PositiveFloat,
                      PositiveInt)

from .base import BaseCommand, DataModel, RTime, Server
from .bind import BindResolver
from . import addmean


class ARData(DataModel):
    P: RTime = 0.0
    mean: RTime = 0.0
    cnt: NonNegativeInt = 0
    kth: NonNegativeInt = 0
    rqx: RTime = 0.0
    rqy: RTime = 0.0
    mean_sq: NonNegativeFloat = 0.0
    mean_xy: NonNegativeFloat = 0.0
    a: NonNegativeFloat = 0.0

class AR1Resolver(BindResolver):
    """
    AR-1 Autoregression time series algorithm.
    """

    class Params(BindResolver.Params):
        p: PositiveInt = 4
        'Minimium sample size before using AR prediction for a server'
        m: PositiveInt = 100
        'Maximum number of queries before a slow server is tried again'
        amin: PositiveFloat = 0.1
        'Minumum value for AR volatility parameter (alpha)'
        amax: PositiveFloat = 0.9
        'Maximum value for AR volatility parameter (alpha)'

    class Config(BindResolver.Config):
        params: AR1Resolver.Params

    params: AR1Resolver.Params
    AR: dict[Server, ARData]

    def __init__(self, config: Any) -> None:
        super().__init__(config)
        self.AR = {S: ARData() for S in self.servers}

    def adjust(self, S: Server, R: RTime) -> None:
        super().adjust(S, R)
        for Si, ARi in self.AR.items():
            if Si == S:
                ARi.kth = self.count
                ARi.cnt = self.counts[Si]
                ARi.mean = self.means[Si]
                ARi.mean_sq = addmean(R**2, ARi.mean_sq, ARi.cnt)
                ARi.rqy, ARi.rqx = ARi.rqx, R
                if ARi.cnt > 1:
                    ARi.mean_xy = addmean(ARi.rqx * ARi.rqy, ARi.mean_xy, ARi.cnt - 1)
                    araw = (ARi.mean_xy - ARi.mean**2) / (ARi.mean_sq - ARi.mean**2)
                    ARi.a = max(self.params.amin, min(self.params.amax, araw))
            if ARi.cnt >= self.params.p:
                k = self.count - ARi.kth
                ARi.P = ARi.a**k * ARi.rqx + (1 - ARi.a**k) * ARi.mean

    def select(self) -> Server:
        lo = None
        stale = []
        for Si, ARi in self.AR.items():
            Ri = ARi.P or self.SR[Si]
            if self.count - ARi.kth > self.params.m:
                stale.append(Si)
            elif lo is None or Ri < lo:
                lo = Ri
                bests = [Si]
            elif Ri == lo:
                bests.append(Si)
        return random.choice(stale or bests)

    def state(self) -> dict[str, Any]:
        return dict(
            AR={
                Si: ARi.model_dump()
                for Si, ARi in sorted(
                    self.AR.items(),
                    key=lambda x: x[1].P)},
            **super().state())

    def load(self, state: dict[str, Any]) -> None:
        super().load(state)
        self.AR = {Si: ARData.model_validate(ARi) for Si, ARi in state['AR'].items()}

class Command(BaseCommand):
    description: ClassVar = 'AR-1 algorithm demo'
    resolver_class: ClassVar = AR1Resolver

if __name__ == '__main__':
    Command.main()

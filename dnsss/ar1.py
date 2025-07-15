from __future__ import annotations

import random
from typing import Any, ClassVar

from pydantic import NonNegativeFloat, NonNegativeInt, PositiveInt

from .base import BaseCommand, DataModel, RTime, Server
from .bind import BindResolver


class Config(DataModel):
    param_p: PositiveInt = 4
    param_m: PositiveInt = 100

class ARData(DataModel):
    P: RTime = 0.0
    kth: NonNegativeInt = 0
    cnt: NonNegativeInt = 0
    rqx: RTime = 0.0
    rqy: RTime = 0.0
    mean: RTime = 0.0
    mean_sq: NonNegativeFloat = 0.0
    mean_xy: NonNegativeFloat = 0.0
    a: NonNegativeFloat = 0.0

class Ar1Resolver(BindResolver):
    """
    AR-1 Autoregression time series algorithm.
    """

    def __init__(self, config: Any) -> None:
        super().__init__(config)
        config: Config = Config.model_validate(config)
        self.param_p = config.param_p
        self.param_m = config.param_m
        self.AR = {S: ARData() for S in self.servers}

    def adjust(self, S: Server, R: RTime) -> None:
        super().adjust(S, R)
        for Si, ARi in self.AR.items():
            if Si == S:
                ARi.kth = self.count
                ARi.cnt = self.counts[Si]
                ARi.mean = self.means[Si]
                ARi.mean_sq = (ARi.mean_sq * (ARi.cnt - 1) + R**2) / ARi.cnt
                ARi.rqy, ARi.rqx = ARi.rqx, R
                if ARi.cnt > 1:
                    ARi.mean_xy = (ARi.mean_xy * (ARi.cnt - 2) + (ARi.rqx * ARi.rqy)) / (ARi.cnt - 1)
                    ARi.a = (ARi.mean_xy - ARi.mean**2) / (ARi.mean_sq - ARi.mean**2)
                    ARi.a = max(0.1, min(0.9, ARi.a))
            if ARi.cnt < self.param_p:
                continue
            k = self.count - ARi.kth
            ARi.P = ARi.a**k * ARi.rqx + (1 - ARi.a**k) * ARi.mean

    def select(self) -> Server:
        lo = None
        for Si, ARi in self.AR.items():
            Ri = ARi.P or self.SR[Si]
            if lo is None or Ri < lo:
                lo = Ri
                bests = [Si]
            elif Ri == lo or self.count - ARi.kth > self.param_m:
                bests.append(Si)
        return random.choice(bests)

    def stateinfo(self) -> dict[str, Any]:
        return dict(
            AR={
                Si: self.AR[Si].model_dump(mode='json')
                for Si in sorted(self.AR, key=lambda S: self.AR[S].P)},
            **super().stateinfo())

class Command(BaseCommand):
    description: ClassVar = 'AR-1 algorithm demo'
    resolver_class: ClassVar = Ar1Resolver

if __name__ == '__main__':
    Command.main()

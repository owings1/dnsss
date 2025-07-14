from __future__ import annotations

import random
from typing import Any, ClassVar

from pydantic import PositiveFloat

from . import byvalue
from .base import BaseCommand, BaseResolver, DataModel, RTime, Server


class Config(DataModel):
    initial: PositiveFloat = 0.05
    param_a: PositiveFloat = 0.7
    param_g: PositiveFloat = 0.98

class BindResolver(BaseResolver):

    def __init__(self, config: Any) -> None:
        super().__init__(config)
        config: Config = Config.model_validate(config)
        self.param_a = config.param_a
        self.param_g = config.param_g
        self.SR = dict.fromkeys(self.servers, config.initial)

    def adjust(self, S: Server, R: RTime) -> None:
        a, g = self.param_a, self.param_g
        for Si, Ri in self.SR.items():
            if Si == S:
                r = a * Ri + (1 - a) * R
            else:
                r = g * Ri
            self.SR[Si] = r

    def select(self) -> Server:
        lo = None
        for Si, Ri in self.SR.items():
            if lo is None or Ri < lo:
                lo = Ri
                bests = [Si]
            elif Ri == lo:
                bests.append(Si)
        return random.choice(bests)
        
    def stateinfo(self) -> dict[str, Any]:
        return dict(SR=dict(sorted(self.SR.items(), key=byvalue))) | super().stateinfo()

class Command(BaseCommand):
    description: ClassVar = 'Bind algorithm demo'
    resolver_class: ClassVar = BindResolver

if __name__ == '__main__':
    Command.main()

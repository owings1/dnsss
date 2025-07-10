from __future__ import annotations

from typing import Any, ClassVar

from pydantic import PositiveFloat

from . import byvalue
from .base import BaseCommand, BaseResolver, DataModel, RTime, Server


class Config(DataModel):
    initial: PositiveFloat = 0.05
    params: tuple[PositiveFloat, PositiveFloat] = (0.7, 0.98)

class Resolver(BaseResolver):

    def __init__(self, config: Any) -> None:
        super().__init__(config)
        config: Config = Config.model_validate(config)
        self.params = config.params
        self.SR = dict.fromkeys(self.servers, config.initial)

    def adjust(self, S: Server, R: RTime) -> None:
        a, g = self.params
        lo = None
        for Si, Ri in self.SR.items():
            if Si == S:
                r = a * Ri + (1 - a) * R
            else:
                r = g * Ri
            if lo is None or r < lo:
                lo = r
                self.Snext = [Si]
            elif r == lo:
                self.Snext.append(Si)
            self.SR[Si] = r

    def stateinfo(self) -> dict[str, Any]:
        return dict(SR=dict(sorted(self.SR.items(), key=byvalue))) | super().stateinfo()

class Command(BaseCommand):
    description: ClassVar = 'Bind algorithm demo'
    resolver_class: ClassVar = Resolver

if __name__ == '__main__':
    Command.main()

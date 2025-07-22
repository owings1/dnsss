from __future__ import annotations

import random
from typing import Any, ClassVar

from pydantic import PositiveFloat

from . import byvalue
from .base import BaseResolver, RTime, Server
from .cli import BaseCommand


class BindResolver(BaseResolver):

    class Params(BaseResolver.Params):
        o: RTime = 0.05
        'The initial value for server times'
        a: PositiveFloat = 0.7
        'Selected server discount constant'
        g: PositiveFloat = 0.98
        'Non-selected server discount constant'

    class Config(BaseResolver.Config):
        params: BindResolver.Params

    params: BindResolver.Params
    SR: dict[Server, RTime]

    def __init__(self, config: Any) -> None:
        super().__init__(config)
        self.SR = dict.fromkeys(self.servers, self.params.o)

    def adjust(self, S: Server, R: RTime) -> None:
        super().adjust(S, R)
        a, g = self.params.a, self.params.g
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
        
    def state(self, *, terse: bool = False) -> dict[str, Any]:
        return dict(
            SR=dict(sorted(self.SR.items(), key=byvalue)),
            **super().state())

    def load(self, state: dict[str, Any]) -> None:
        super().load(state)
        self.SR = state['SR']

class Command(BaseCommand):
    description: ClassVar = 'Bind algorithm demo'
    resolver_class: ClassVar = BindResolver
    slug: ClassVar = 'bind'

if __name__ == '__main__':
    Command.main()

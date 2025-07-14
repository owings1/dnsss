from __future__ import annotations

from typing import Any, ClassVar

from pydantic import PositiveInt

from .base import BaseCommand, DataModel, RTime, Server
from .bind import BindResolver


class Config(DataModel):
    param_k: PositiveInt = 4

class BmodResolver(BindResolver):
    """
    Bind algorithm with the following optimization:
    
    When adjusting the computed R value for the server S that was just queried,
    use the maximum of:

         i. the value as computed according to the original bind algorithm, and
        ii. the mean obvserved response time of the last k=4 queries to S.

    The idea is increase the penalty for slower-responding servers, so that they
    are contacted less often, but to keep k sufficiently small to allow for
    recovery of temporary increased latency.
    """

    def __init__(self, config: Any) -> None:
        super().__init__(config)
        config: Config = Config.model_validate(config)
        self.param_k = config.param_k
        self.kmeans = dict.fromkeys(self.servers, 0.0)

    def adjust(self, S: Server, R: RTime) -> None:
        super().adjust(S, R)
        k = self.param_k
        if self.counts[S] <= k:
            self.kmeans[S] = self.means[S]
        else:
            self.kmeans[S] = ((self.kmeans[S] * (k - 1)) + R) / k
        self.SR[S] = max(self.SR[S], self.kmeans[S])

class Command(BaseCommand):
    description: ClassVar = 'Bmod algorithm demo'
    resolver_class: ClassVar = BmodResolver

if __name__ == '__main__':
    Command.main()

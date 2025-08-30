from __future__ import annotations

import random
import re
import time
from typing import Any

import dns.resolver

from ..models import *
from ..utils import *

__all__ = ()

class Resolver:
    """
    Resolver base class
    """

    class Config(BaseModel):
        servers: list[Server] = Field(min_length=1)
        'Non-empty list of server addresses'
        timeout: PositiveFloat = 5.0
        'Default server timeout seconds'
        tcp: bool = False
        'Whether to use TCP'

    counts: dict[Server, NonNegativeInt]
    'Total queries per server'
    mean: RTime
    'Running mean response time for all queries'
    means: dict[Server, RTime]
    'Running mean response time per server'
    anomaly: Anomaly|None
    'For injecting latency anomalies at runtime'

    @property
    def count(self) -> NonNegativeInt:
        'Total queries made to all servers'
        return sum(self.counts.values())

    def __init__(self, config: Any) -> None:
        self.config = self.Config.model_validate(config)
        self.mean = 0.0
        self.counts = dict.fromkeys(self.config.servers, 0)
        self.means = dict.fromkeys(self.config.servers, 0.0)
        self.anomaly = None

    def adjust(self, S: Server, R: RTime) -> None:
        """
        Update any calculations & state as needed from the observed response
        time of a server. Subclasses should make sure to call super.
        """
        self.counts[S] += 1
        self.mean = addmean(R, self.mean, self.count)
        self.means[S] = addmean(R, self.means[S], self.counts[S])

    def select(self) -> Server:
        """
        Select the server for the next query according to the algorithm
        implementation. Subclasses should override this method.
        """
        return random.choice(self.config.servers)

    def lifetime(self, S: Server) -> PositiveFloat:
        """
        Get the timeout for the next query to a server.
        """
        return self.config.timeout

    def state(self, *, terse: bool = False) -> dict[str, Any]:
        """
        Return a dict representation of the current state, for display, export,
        and serialization. Subclasses should make sure to call super and merge
        the return value.
        """
        return dict(
            count=self.count,
            counts=dvsorted(self.counts, reverse=True),
            mean=self.mean,
            means=dvsorted(self.means))

    def load(self, state: dict[str, Any]) -> None:
        """
        Load a state dict as returned by `.state()`. Subclasses should make sure
        to call super.
        """
        for key in ('counts', 'mean', 'means'):
            setattr(self, key, state[key])
        self.config.servers = list(self.counts)

    def query(self, question: Any) -> Response:
        """
        Make a DNS query. Selects the server with `.select()`, and calls
        `.adjust()` before returning. Sublcasses should not need to override
        this method.
        """
        q = Question.model_validate(question)
        S = self.select()
        delay = 0.0
        if self.anomaly:
            self.anomaly.begin()
            if self.anomaly.expired():
                self.anomaly = None
            elif re.match(self.anomaly.pat, S):
                delay += self.anomaly.delay
        delay = valrtime(delay)
        lifetime = max(0.0, self.lifetime(S) - delay)
        resolve = dns.resolver.make_resolver_at(S).resolve
        t = time.monotonic() - delay
        try:
            rep = resolve(
                **q.model_dump(),
                raise_on_no_answer=False,
                lifetime=lifetime,
                tcp=self.config.tcp)
        except dns.resolver.NXDOMAIN:
            rep = []
        finally:
            R = time.monotonic() - t
            self.adjust(S, R)
        return Response(S=S, R=R, q=q, a=[*map(str, rep)])
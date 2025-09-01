from __future__ import annotations

import random
import re
import time
from typing import Any, Annotated

import dns.resolver

from ..models import *
from ..utils import *

__all__ = ()

class Config(BaseModel):
    servers: list[Server] = Field(min_length=1)
    'Non-empty list of server addresses'
    timeout: PositiveFloat = 5.0
    'Default server timeout seconds'
    tcp: bool = False
    'Whether to use TCP'

class State(BaseModel):
    SM: Annotated[
        dict[Server, RunningMean],
        PlainSerializer(lambda x: dvsorted(x))] = Field(default_factory=dict)
    'Running means of server response times'
    M: RunningMean = Field(default_factory=RunningMean)
    'Running mean response time for all queries'

    def post_config_init(self, config: Config) -> None:
        self.SM = {Si: RunningMean() for Si in config.servers}

    def report(self) -> dict[str, Any]:
        return self.model_dump(context=dict(terse=True))

class Resolver(BaseModel):
    'Resolver base class'
    config: Config
    state: State = Field(default_factory=State)
    delayers: list[Delayer] = Field(default_factory=list)
    'For injecting latency simulations at runtime'

    def model_post_init(self, context: Any, /) -> None:
        self.state.post_config_init(self.config)

    def adjust(self, S: Server, R: NonNegativeFloat) -> None:
        """
        Update any calculations & state as needed from the observed response
        time of a server. Subclasses should make sure to call super.
        """
        self.state.SM[S].observe(R)
        self.state.M.observe(R)

    def select(self, q: Question) -> Server:
        """
        Select the server for the next query according to the algorithm
        implementation. Subclasses should override this method.
        """
        return random.choice([*self.state.SM])

    def lifetime(self, S: Server, q: Question) -> PositiveFloat:
        """
        Get the timeout for a query to a server.
        """
        return self.config.timeout

    def query(self, q: Question) -> Response:
        """
        Make a DNS query. Selects the server with `.select()`, and calls
        `.adjust()` before returning. Sublcasses should not need to override
        this method.
        """
        q = Question.model_validate(q)
        S = self.select(q)
        for delayer in self.delayers:
            if re.match(delayer.pat, S):
                delay = delayer.delay
                break
        else:
            delay = 0.0
        lifetime = self.lifetime(S, q)
        delay = valnnf(min(delay, lifetime))
        lifetime -= delay
        where, pstr = f'{S}@53'.split('@')[:2]
        resolve = dns.resolver.make_resolver_at(where, int(pstr)).resolve
        t = time.monotonic() - delay
        try:
            rep = resolve(
                **q.model_dump(),
                raise_on_no_answer=False,
                lifetime=lifetime,
                tcp=self.config.tcp)
        except dns.resolver.NXDOMAIN:
            rep = []
        except dns.resolver.LifetimeTimeout as err:
            rep = [f'{err}']
        finally:
            R = time.monotonic() - t
            self.adjust(S, R)
        return Response(S=S, R=R, q=q, a=[*map(str, rep)])
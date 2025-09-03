from __future__ import annotations

import functools
import random
import re
import time
from typing import Annotated, Any, Iterable

import dns.resolver

from ..models import *
from ..utils import *

__all__ = ()

class Params(BaseModel):
    pass

class Config(BaseModel):
    servers: list[Server] = Field(
        min_length=1,
        default_factory=lambda: dns.resolver.get_default_resolver().nameservers,
        validate_default=True)
    'Non-empty list of server addresses'
    rules: Annotated[
        list[DomainRule],
        AfterValidator(sorted)] = Field(default_factory=list)
    'Domain rules'
    params: Params = Field(default_factory=Params)
    'Algorithm-specific parameters'
    timeout_max: PositiveFloat = 5.0
    'Default/max server timeout seconds'
    timeout_min: PositiveFloat = 1.0
    'Minimum server timeout seconds'
    retries_max: NonNegativeInt = 3
    'Maximum number of retries for timeouts'
    tcp: bool = False
    'Whether to use TCP'

class State(BaseModel):
    SM: Annotated[
        dict[Server, RunningMean],
        PlainSerializer(dvsorted)] = Field(default_factory=dict)
    'Running means of server response times'
    M: RunningMean = Field(default_factory=RunningMean)
    'Running mean response time for all queries'
    params: Params = Field(default_factory=Params, exclude=True)

    def addserver(self, S: Server) -> None:
        'Initialize server state'
        self.SM[S] = RunningMean()

    def observe(self, S: Server, R: NonNegativeFloat, code: Rcode, servers: list[Server]) -> None:
        """
        Update any calculations & state as needed from the observed response
        time of a server. Subclasses should make sure to call super.
        """
        self.SM[S].observe(R)
        self.M.observe(R)

    def ranked(self, servers: Iterable[Server]) -> list[Server]:
        servers = list(servers)
        # Shuffle the list before sorting to randomize servers of equal rank
        random.shuffle(servers)
        servers.sort(key=self.rank)
        return servers

    def rank(self, S: Server) -> float:
        """
        Compute rank order of the server for the next query according to the
        algorithm implementation. Subclasses should override this method.
        """
        return random.random()

    def report(self) -> dict[str, Any]:
        return self.model_dump(context=dict(terse=True))

    def load(self, data: Any):
        servers = list(self.SM)
        mydata = self.model_dump()
        other = self.model_validate(mydata | self.model_validate(data).model_dump())
        for name in mydata:
            setattr(self, name, getattr(other, name))
        for Si in servers:
            if Si not in self.SM:
                self.addserver(Si)

class Resolver(BaseModel):
    'Resolver base class'
    config: Config = Field(default_factory=Config)
    state: State = Field(default_factory=State)
    delayers: list[Delayer] = Field(default_factory=list)
    'For injecting latency simulations at runtime'

    def model_post_init(self, context: Any, /) -> None:
        super().model_post_init(context)
        self.state.params = self.config.params
        for Si in self.config.servers:
            self.state.addserver(Si)
        for rule in self.config.rules:
            for Si in rule.servers:
                if Si not in self.state.SM:
                    self.state.addserver(Si)

    def lifetime(self, S: Server, q: Question) -> PositiveFloat:
        """
        Get the timeout for a query to a server.
        """
        return self.config.timeout_max

    def select(self, q: Question) -> list[Server]:
        name = q.qname.rstrip('.')
        for rule in self.config.rules:
            if name == rule.domain or name.endswith(f'.{rule.domain}'):
                return rule.servers
        return self.config.servers

    def query(self, q: Question) -> Response:
        """
        Make a DNS query. Sublcasses should not need to override this method.
        """
        q = Question.model_validate(q)
        servers = self.select(q)
        failed = []
        rep = None
        while not rep:
            servers = self.state.ranked(servers)
            if not servers:
                raise ValueError(f'No servers {q=}')
            for S in servers:
                for delayer in self.delayers:
                    if re.match(delayer.pat, S):
                        delay = delayer.delay
                        break
                else:
                    delay = 0.0
                lifetime = max(
                    self.config.timeout_min,
                    min(self.config.timeout_max, self.lifetime(S, q)))
                delay = valnnf(min(delay, lifetime))
                lifetime -= delay
                resolve = _resolver(S)
                t = time.monotonic() - delay
                code, rset = resolve(q, lifetime=lifetime, tcp=self.config.tcp)
                R = time.monotonic() - t
                self.state.observe(S, R, code, servers)
                if code != 'TIMEOUT' or len(failed) >= self.config.retries_max:
                    rep = Response(S=S, R=R, q=q, code=code, rset=rset, failed=failed or None)
                    break
                failed.append(S)
        return rep

@functools.cache
def _resolver(S: Server):
    where, pstr = f'{S}@53'.split('@')[:2]
    f = dns.resolver.make_resolver_at(where, int(pstr)).resolve
    def r(q: Question, lifetime: NonNegativeFloat, tcp: bool) -> tuple[Rcode, Rset]:
        try:
            rep = f(
                **q.model_dump(),
                raise_on_no_answer=False,
                lifetime=lifetime,
                tcp=tcp)
        except dns.resolver.NXDOMAIN:
            code = 'NXDOMAIN'
            rep = []
        except dns.resolver.LifetimeTimeout:
            code = 'TIMEOUT'
            rep = []
        else:
            code = rep.response.rcode().name
        return code, [*map(str, rep)]
    return r

from __future__ import annotations

import functools
import random
import re
import time
from collections import defaultdict
from typing import Annotated, Any, Callable, Iterable

import dns.resolver

from ..models import *
from ..utils import *

type ResolveFuncRet = tuple[Rcode, Rset, NonNegativeFloat]
type ResolveFunc = Callable[[Question, NonNegativeFloat, bool], ResolveFuncRet]

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
    params: Params = Field(default_factory=Params, frozen=True)
    'Algorithm-specific parameters'
    timeout_max: PositiveFloat = 5.0
    'Default/max server timeout seconds'
    timeout_min: PositiveFloat = 1.0
    'Minimum server timeout seconds'
    retries_max: NonNegativeInt = 3
    'Maximum number of retries for timeouts'
    tcp: bool = False
    'Whether to use TCP'

class State(RunningMean):
    SM: Annotated[
        dict[Server, RunningMean],
        PlainSerializer(dvsorted)] = Field(default_factory=dict)
    'Running means of server response times'
    params: Params = Field(default_factory=Params, exclude=True)
    model_config = ConfigDict(sfields=['SM'])

    def add(self, S: Server) -> None:
        'Initialize server state'
        if S not in self.SM:
            self.SM[S] = RunningMean()

    def observe(self, S: Server, R: NonNegativeFloat, code: Rcode, servers: list[Server]) -> None:
        """
        Update any calculations & state as needed from the observed response
        time of a server. Subclasses should make sure to call super.
        """
        self.SM[S].observe(R)
        super().observe(R)

    def rank(self, S: Server) -> PositiveFloat:
        """
        Compute rank order of the server for the next query according to the
        algorithm implementation. Subclasses should override this method.
        """
        return random.random()

    def ranked(self, servers: Iterable[Server]) -> list[Server]:
        'Return a rank ordered list of the given servers'
        servers = list(servers)
        # Shuffle the list before sorting to randomize servers of equal rank
        random.shuffle(servers)
        servers.sort(key=self.rank)
        return servers

    def load(self, data: Any) -> None:
        'Load saved state data'
        servers = list(self.SM)
        data = self.model_dump() | self.model_validate(data).model_dump()
        other = self.model_validate(data)
        for name in data:
            setattr(self, name, getattr(other, name))
        for Si in servers:
            self.add(Si)

    def report(self, *, table: bool|str = False, **kw) -> dict[str, Any]:
        'Display data'
        data = super().report(**kw)
        data['servers'] = defaultdict(dict)
        for field in self.model_config.get('sfields', []):
            key = str(field).removeprefix('S')
            for Si, Vi in data.pop(field, {}).items():
                data['servers'][Si][key] = Vi
        if table:
            rows = [
                dict(Server=Si)|dkpathed(SVi)
                for Si, SVi in data['servers'].items()]
            tablefmt = None if table is True else table
            data['servers'] = tablestr(rows, headers='keys', tablefmt=tablefmt)
        else:
            data['servers'] = dict(data['servers'])
        return data

class Resolver(BaseModel):
    'Resolver base class'
    config: Config = Field(default_factory=Config, frozen=True)
    state: State = Field(default_factory=State, frozen=True)
    delayers: list[Delayer] = Field(default_factory=list)
    'For injecting latency simulations at runtime'

    def model_post_init(self, context: Any, /) -> None:
        super().model_post_init(context)
        self.state.params = self.config.params
        for Si in self.config.servers:
            self.state.add(Si)
        for rule in self.config.rules:
            for Si in rule.servers:
                self.state.add(Si)

    def lifetime(self, S: Server, q: Question) -> PositiveFloat:
        """
        Get the timeout for a query to a server.
        """
        return self.config.timeout_max

    def select(self, q: Question) -> list[Server]:
        'Select the list of servers for a question based on domain rule'
        for rule in self.config.rules:
            if rule.matches(q.qname):
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
                resolve = resolve_func(S)
                t = time.monotonic() - delay
                code, rset, R = resolve(q, lifetime=lifetime, tcp=self.config.tcp)
                R += time.monotonic() - t
                self.state.observe(S, R, code, servers)
                if code != 'TIMEOUT' or len(failed) >= self.config.retries_max:
                    rep = Response(S=S, R=R, q=q, code=code, rset=rset, failed=failed or None)
                    break
                failed.append(S)
        return rep

@functools.cache
def resolve_func(S: Server) -> ResolveFunc:
    where, pstr = (f'{S}'.split('@', maxsplit=1) + [None])[:2]
    if where.startswith('mock'):
        mvals = pstr and pstr.split(',') or []
        m = MockServer(**dict(zip(['r', 'volatility'], mvals)))
        return make_mock_resolve_func(m)
    else:
        port = int(pstr or 53)
        return make_dns_resolve_func(where, port)

def make_dns_resolve_func(where: str, port: int = 53) -> ResolveFunc:
    f = dns.resolver.make_resolver_at(where, port).resolve
    def resolve(q: Question, lifetime: NonNegativeFloat, tcp: bool) -> ResolveFuncRet:
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
        return code, [*map(str, rep)], 0.0
    return resolve

def make_mock_resolve_func(mock: MockServer) -> ResolveFunc:
    mock = MockServer.model_validate(mock)
    def resolve(q: Question, lifetime: NonNegativeFloat, tcp: bool) -> ResolveFuncRet:
        d = random.uniform(0, mock.volatility)
        R = mock.r + mock.r * d
        rset = []
        if R >= lifetime:
            code = 'TIMEOUT'
            R = lifetime
        else:
            code = 'NOERROR'
            rset += ['mock']
        return code, rset, valnnf(R)
    return resolve

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
    timeout_max: PositiveFloat = 5.0
    'Default/max server timeout seconds'
    timeout_min: PositiveFloat = 1.0
    'Minimum server timeout seconds'
    retries_max: NonNegativeInt = 3
    'Maximum number of retries for timeouts'
    tcp: bool = False
    'Whether to use TCP'
    params: Params = Field(default_factory=Params, frozen=True)
    'Algorithm-specific parameters'

class State(RunningMean):
    SM: Annotated[
        dict[Server, RunningMean],
        PlainSerializer(dvsorted)] = Field(default_factory=dict)
    'Running means of server response times'
    params: Params = Field(default_factory=Params, exclude=True)
    'Reference to the algorithm params'
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
        # Clean merge the data
        data = self.model_dump() | self.model_validate(data).model_dump()
        other = self.model_validate(data)
        for name in data:
            setattr(self, name, getattr(other, name))
        for Si in servers:
            self.add(Si)

    def report(self, *, table: bool|str = False, **kw) -> dict[str, Any]:
        "Compact display data"
        data = super().report(**kw)
        sdata = defaultdict(dict)
        for field in self.model_config.get('sfields', []):
            key = str(field).removeprefix('S')
            for Si, Vi in data.pop(field, {}).items():
                sdata[Si][key] = Vi
        sdata = dict(sdata)
        if table:
            rows = [
                dict(Server=Si)|dkpathed(SVi)
                for Si, SVi in sdata.items()]
            tablefmt = None if table is True else table
            sdata = tablestr(rows, headers='keys', tablefmt=tablefmt)
        data['servers'] = sdata
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
        for server in self.config.servers:
            self.state.add(server)
        for rule in self.config.rules:
            for server in rule.servers:
                self.state.add(server)

    def select(self, q: Question) -> list[Server]:
        """
        Returns all applicable servers for a question based on domain rule
        """
        for rule in self.config.rules:
            if rule.matches(q.qname):
                return rule.servers
        return self.config.servers

    def lifetime(self, S: Server, q: Question) -> PositiveFloat:
        """
        Get the timeout for a query to a server.
        """
        return self.config.timeout_max

    def query(self, q: Question) -> Response:
        """
        Perform a DNS query with retries.
        """
        q = Question.model_validate(q)
        # Get all applicable servers based on domain rules
        servers = self.select(q)
        failed: list[Server] = []
        rep: Response|None = None
        while not rep:
            # Rank order the servers
            servers = self.state.ranked(servers)
            if not servers:
                raise ValueError(f'No servers {q=}')
            for S in servers:
                # Apply any delay anomalies
                for delayer in self.delayers:
                    if re.match(delayer.pattern, S):
                        delay = delayer.delay
                        break
                else:
                    delay = 0.0
                # Compute the timeout to send to the backend
                lifetime = max(
                    self.config.timeout_min,
                    min(self.config.timeout_max, self.lifetime(S, q)))
                delay = valnnf(min(delay, lifetime))
                lifetime -= delay
                # Get the response from the backend
                backend = resolve_backend(S)
                t = time.monotonic() - delay
                code, rset, R = backend(q, lifetime=lifetime, tcp=self.config.tcp)
                R += time.monotonic() - t
                # Report the response time & result
                self.state.observe(S, R, code, servers)
                if code != 'TIMEOUT' or len(failed) >= self.config.retries_max:
                    # A successful response, or max retries reached with TIMEOUT
                    rep = Response(S=S, R=R, q=q, code=code, rset=rset, failed=failed or None)
                    break
                failed.append(S)
        return rep

@functools.cache
def resolve_backend(server: Server) -> ResolveFunc:
    'Create the backend resolve function for the server'
    if server.startswith('mock'):
        configstr, = (server.split('@', maxsplit=1)[1:] or [''])
        opts = dict(
            itemstr.split('=') for itemstr in
            filter(None, configstr.split(',')))
        return _mock_backend(**opts)
    return _dnspython_backend(*server.split('@', maxsplit=1))

def _dnspython_backend(where: str, port: int|str = 53) -> ResolveFunc:
    "Make a backend resolve function for a server/port using dnspython"
    backend = dns.resolver.make_resolver_at(where, int(port))
    def resolve(q: Question, lifetime: NonNegativeFloat, tcp: bool) -> ResolveFuncRet:
        try:
            rep = backend.resolve(
                **q.model_dump(),
                raise_on_no_answer=False,
                lifetime=lifetime,
                tcp=tcp)
        except dns.resolver.NXDOMAIN:
            code = 'NXDOMAIN'
            rset = []
        except dns.resolver.LifetimeTimeout:
            code = 'TIMEOUT'
            rset = []
        else:
            code = rep.response.rcode().name
            rset = [(
                f'{rep.rrset.name} '
                f'{rep.rrset.ttl} '
                f'{rep.rdclass.name} '
                f'{x.rdtype.name} '
                f'{x}') for x in rep]
        return code, rset, 0.0
    return resolve

def _mock_backend(**opts) -> ResolveFunc:
    "Make a mock backend resolve function"
    mock = MockServer.model_validate(opts)
    def resolve(q: Question, lifetime: NonNegativeFloat, tcp: bool) -> ResolveFuncRet:
        d = random.uniform(0, mock.v)
        R = mock.r * (1 + d)
        rset = []
        if R >= lifetime:
            code = 'TIMEOUT'
            R = lifetime
        else:
            code = 'NOERROR'
        return code, rset, valnnf(R)
    return resolve

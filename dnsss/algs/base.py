from __future__ import annotations

import functools
import random
import re
import time
from collections import defaultdict
from itertools import chain, islice
from threading import RLock
from types import MappingProxyType as MapProxy
from typing import Annotated, Any, Iterable, Mapping

from .. import backends
from ..models import *
from ..utils import *

__all__ = ()

class Params(DataModel):
    'Algorithm-specific parameters'
    pass

class Config(DataModel):
    servers: tuple[Server, ...] = Field(
        min_length=1,
        frozen=True,
        validate_default=True,
        default_factory=lambda: default_nameservers())
    'Default server addresses'
    rules: Annotated[
        tuple[DomainRule, ...],
        AfterValidator(lambda x: tuple(sorted(x)))] = Field(
        default=(),
        frozen=True)
    'Domain forwarding rules'
    timeout_max: PositiveFloat = 5.0
    'Default/max server timeout seconds'
    timeout_min: PositiveFloat = 1.0
    'Minimum server timeout seconds'
    retries_max: NonNegativeInt = 3
    'Maximum number of retries for timeouts'
    tcp: bool = False
    'Whether to use TCP'
    params: Params = Field(default_factory=Params, frozen=True)
    'Reference to the algorithm params'

class State(RunningMean):
    SM: Annotated[
        dict[Server, RunningMean],
        PlainSerializer(dvsorted)] = Field(default_factory=dict)
    'Running means of server response times'
    params: Params = Field(default_factory=Params, exclude=True)
    'Reference to the algorithm params'
    model_config = ConfigDict(server_dict_fields=['SM'])

    def add(self, server: Server) -> None:
        'Initialize server state'
        if server not in self.SM:
            self.SM[server] = RunningMean()

    def observe(self, server: Server, rtime: NonNegativeFloat, code: Rcode, servers: list[Server]) -> None:
        """
        Update any calculations & state as needed from the observed response
        time of a server. Subclasses should make sure to call super.
        """
        with self._lock:
            self.SM[server].observe(rtime)
            super().observe(rtime)

    def rank(self, server: Server) -> PositiveFloat:
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
        with self._lock:
            servers.sort(key=self.rank)
        return servers

    def load(self, data: Any) -> None:
        'Load saved state data'
        servers = list(self.SM)
        # Clean merge the data
        data = self.model_dump() | self.model_validate(data).model_dump()
        other = self.model_validate(data)
        for name in data:
            if hasattr(other, name):
                setattr(self, name, getattr(other, name))
        for Si in servers:
            self.add(Si)

    def report(self, **kw) -> dict[str, Any]:
        "Formatted display data"
        data = super().report(**kw)
        servers = defaultdict(dict)
        for field in self.model_config.get('server_dict_fields', []):
            key = str(field).removeprefix('S')
            for server, info in data.pop(field, {}).items():
                servers[server][key] = info
        servers = {
            server: dict(server=server)|dkpathed(info)
            for server, info in servers.items()}
        data['servers'] = servers
        return data

    def model_post_init(self, context: Any, /) -> None:
        super().model_post_init(context)
        self._lock = RLock()

class Resolver(DataModel):
    'Resolver base class'
    config: Config = Field(default_factory=Config, frozen=True)
    state: State = Field(default_factory=State, frozen=True)
    delayers: list[Delayer] = Field(default_factory=list)
    'For injecting latency simulations at runtime'

    def select(self, q: Question) -> tuple[list[Server], ServersTag]:
        """
        Returns all applicable servers for a question based on forwarding rules
        """
        for base in self.config.rules:
            if base.matches(q.qname):
                tag = base.tag
                break
        else:
            base = self.config
            tag = 'DFLT'
        return list(base.servers), tag

    def lifetime(self, server: Server, q: Question) -> PositiveFloat:
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
        servers, tag = self.select(q)
        failed: list[Server] = []
        while True:
            # Rank order the servers
            servers = self.state.ranked(servers)
            if not servers:
                raise ValueError(f'No servers {q=}')
            for server in servers:
                # Apply any delay anomalies
                for delayer in self.delayers:
                    if re.match(delayer.pattern, server):
                        delay = delayer.delay
                        break
                else:
                    delay = 0.0
                # Compute the timeout to send to the backend
                lifetime = max(
                    self.config.timeout_min,
                    min(self.config.timeout_max, self.lifetime(server, q)))
                delay = min(delay, lifetime)
                lifetime -= delay
                # Get the response from the backend
                backend = backends.resolve_backend(server)
                t = time.monotonic() - delay
                rep = BackendResponse.model_validate(backend(q, lifetime, self.config.tcp))
                rep.rtime += time.monotonic() - t
                # Report the response time & result
                self.state.observe(server, rep.rtime, rep.code, servers)
                if rep.code is rep.code.SERVFAIL and len(failed) < self.config.retries_max:
                    failed.append(server)
                else:
                    # A successful response, or max retries reached with timeout
                    break
            else:
                continue
            break
        return Response(
            **rep.model_dump(),
            server=server,
            q=q,
            tag=tag,
            failed=failed or None)

    def report(self, *, table: bool = False, **kw) -> dict[str, Any]:
        "Formatted data for display & logging"
        groups = self.servergroups
        state = self.state.report(**kw)
        servers = defaultdict(list)
        totals = defaultdict(int)
        # Bucket into groups. A server may appear in more than one group
        unkwn = []
        for server, sdata in state['servers'].items():
            if server not in groups:
                unkwn.append(sdata)
                continue
            for tag in groups[server]:
                servers[tag].append(sdata)
                totals[tag] += self.state.SM[server].count
        # Sort groups by highest total query count
        servers = {
            tag: servers[tag] for tag in
            sorted(servers, key=totals.get, reverse=True)}
        # The unknown servers go last
        if unkwn:
            servers['UNWN'] = unkwn
        if table:
            # Build one big table to have equal column widths
            lines = tablestr(
                chain.from_iterable(servers.values()),
                headers='keys',
                tablefmt='simple').splitlines()
            # Grab the header so we can repeat it
            end = len(lines) - sum(map(len, servers.values()))
            headers = lines[:end]
            # Reslice the lines back into separate tables
            for tag, sdatas in servers.items():
                start, end = end, end + len(sdatas)
                body = islice(lines, start, end)
                servers[tag] = LiteralStr('\n'.join(chain(headers, body)))
        state['servers'] = servers
        return dict(state=state)

    @functools.cached_property
    def servergroups(self) -> Mapping[Server, tuple[str, ...]]:
        'Mapping of server to group names, for reporting & logging'
        builder = {frozenset(self.config.servers): 'DFLT'}
        for rule in self.config.rules:
            key = frozenset(rule.servers)
            rule.tag = builder.setdefault(key, rule.tag or f'GRP{len(builder)}')
        groups = defaultdict(list)
        for key, tag in builder.items():
            for server in sorted(key):
                groups[server].append(tag)
        return MapProxy({
            server: tuple(groups[server]) for server in sorted(groups)})

    def model_post_init(self, context: Any, /) -> None:
        super().model_post_init(context)
        self.state.params = self.config.params
        for server in self.config.servers:
            self.state.add(server)
        for rule in self.config.rules:
            for server in rule.servers:
                self.state.add(server)
        # Preload cached property
        self.servergroups

def default_nameservers() -> list[Server]:
    "Get the list of default system resolvers"
    import dns.resolver
    return list(dns.resolver.get_default_resolver().nameservers)

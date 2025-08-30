from __future__ import annotations

import random
import re
import time
from datetime import datetime, timedelta
from typing import Any

import dns.resolver

from ..utils import addmean, byvalue
from ..models import *

__all__ = ()

class Resolver:

    class Config(BaseModel):
        servers: list[Server] = Field(min_length=1)
        tcp: bool = False

    count: NonNegativeInt
    counts: dict[Server, NonNegativeInt]
    mean: RTime
    means: dict[Server, RTime]
    anomaly: Anomaly|None

    def __init__(self, config: Any) -> None:
        self.config = self.Config.model_validate(config)
        self.count = 0
        self.mean = 0.0
        self.counts = dict.fromkeys(self.config.servers, 0)
        self.means = dict.fromkeys(self.config.servers, 0.0)
        self.anomaly = None

    def adjust(self, S: Server, R: RTime) -> None:
        self.count += 1
        self.counts[S] += 1
        self.mean = addmean(R, self.mean, self.count)
        self.means[S] = addmean(R, self.means[S], self.counts[S])

    def select(self) -> Server:
        return random.choice(self.config.servers)

    def query(self, qname: str, rdtype: RdType = 'A', delay: RTime = 0.0) -> Response:
        if self.anomaly:
            self.anomaly.expiry = (
                self.anomaly.expiry or
                datetime.now() + timedelta(seconds=self.anomaly.duration))
            if datetime.now() > self.anomaly.expiry:
                self.anomaly = None
        q = Question(qname=qname, rdtype=rdtype)
        S = self.select()
        if self.anomaly and re.match(self.anomaly.pat, S):
            delay += self.anomaly.delay
        resolve = dns.resolver.make_resolver_at(S).resolve
        t = time.monotonic() - valrtime(delay)
        try:
            rep = resolve(
                **q.model_dump(),
                raise_on_no_answer=False,
                tcp=self.config.tcp)
        except dns.resolver.NXDOMAIN:
            rep = []
        finally:
            R = time.monotonic() - t
            self.adjust(S, R)
        return Response(S=S, R=R, q=q, a=[*map(str, rep)])

    def state(self, *, terse: bool = False) -> dict[str, Any]:
        return dict(
            count=self.count,
            counts=dict(sorted(self.counts.items(), key=byvalue, reverse=True)),
            mean=self.mean,
            means=dict(sorted(self.means.items(), key=byvalue)))

    def load(self, state: dict[str, Any]) -> None:
        for key in ('count', 'counts', 'mean', 'means'):
            setattr(self, key, state[key])
        self.config.servers = list(self.counts)

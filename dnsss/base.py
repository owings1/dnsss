from __future__ import annotations

import random
import re
import time
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

import dns.resolver
from pydantic import (BaseModel, BeforeValidator, Field, NonNegativeFloat,
                      NonNegativeInt, TypeAdapter, ValidationError)

from . import addmean, byvalue

type Server = str
type RTime = NonNegativeFloat
type Answer = list[str]
type RdType = Annotated[
    Literal['A', 'AAAA', 'CNAME', 'PTR', 'NS', 'TXT', 'MX', 'SOA', 'SRV'],
    BeforeValidator(str.upper)]

valrtime = TypeAdapter(RTime).validate_python

def valpat(value: str):
    try:
        re.compile(value)
    except ValueError:
        raise ValidationError
    return value

class Question(BaseModel):
    qname: str
    rdtype: RdType = 'A'

class Response(BaseModel):
    S: Server
    R: RTime
    q: Question
    a: Answer

class Anomaly(BaseModel):
    pat: Annotated[str, BeforeValidator(valpat)]
    delay: RTime
    duration: NonNegativeInt
    expiry: datetime|None = None

class BaseResolver:
    servers: list[Server]
    params: BaseResolver.Params
    tcp: bool
    count: NonNegativeInt
    counts: dict[Server, NonNegativeInt]
    mean: RTime
    means: dict[Server, RTime]
    anomaly: Anomaly|None

    class Params(BaseModel):
        pass

    class Config(BaseModel):
        servers: list[Server] = Field(min_length=1)
        params: BaseResolver.Params
        tcp: bool = False

    def __init__(self, config: Any) -> None:
        config: BaseResolver.Config = self.Config.model_validate(config)
        self.servers = config.servers
        self.params = config.params
        self.tcp = config.tcp
        self.count = 0
        self.mean = 0.0
        self.counts = dict.fromkeys(self.servers, 0)
        self.means = dict.fromkeys(self.servers, 0.0)
        self.anomaly = None

    def adjust(self, S: Server, R: RTime) -> None:
        self.count += 1
        self.counts[S] += 1
        self.mean = addmean(R, self.mean, self.count)
        self.means[S] = addmean(R, self.means[S], self.counts[S])

    def select(self) -> Server:
        return random.choice(self.servers)

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
            rep = resolve(**q.model_dump(), raise_on_no_answer=False, tcp=self.tcp)
        except dns.resolver.NXDOMAIN:
            rep = []
        finally:
            R = time.monotonic() - t
            self.adjust(S, R)
        return Response(S=S, R=R, q=q, a=[*map(str, rep)])

    def state(self) -> dict[str, Any]:
        return dict(
            count=self.count,
            counts=dict(sorted(self.counts.items(), key=byvalue, reverse=True)),
            mean=self.mean,
            means=dict(sorted(self.means.items(), key=byvalue)))

    def load(self, state: dict[str, Any]) -> None:
        for key in ('count', 'counts', 'mean', 'means'):
            setattr(self, key, state[key])
        self.servers = list(self.counts)

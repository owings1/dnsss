from __future__ import annotations

import enum
import ipaddress
import math
import operator
import random
import re
import time
from functools import cached_property
from typing import Annotated, Any, Callable, Literal, Self

import pydantic
from dnslib import RCODE
from pydantic import (AfterValidator, BeforeValidator, ConfigDict, Field,
                      FieldSerializationInfo, IPvAnyAddress, NegativeInt,
                      NonNegativeFloat, NonNegativeInt, PlainSerializer,
                      PositiveFloat, PositiveInt, SerializationInfo,
                      SerializerFunctionWrapHandler, field_serializer,
                      model_serializer, model_validator)

__all__ = [
    'AfterValidator',
    'Anomaly',
    'BackendResponse',
    'BaseModel',
    'BeforeValidator',
    'ConfigDict',
    'DataModel',
    'Delayer',
    'DomainRule',
    'ErName',
    'Field',
    'IPvAnyAddress',
    'MockServer',
    'NonNegativeFloat',
    'NonNegativeInt',
    'PlainSerializer',
    'Port',
    'PositiveFloat',
    'PositiveInt',
    'Proto',
    'Question',
    'Rcode',
    'RdClass',
    'RdType',
    'Response',
    'Rset',
    'RunningMean',
    'RunningRate',
    'RunningVariance',
    'Server',
    'ServersTag']

type Server = str
type Rset = list[str]
type Domain = Annotated[
    str,
    AfterValidator(lambda x: x.strip('.').lower())]
type Port = Annotated[PositiveInt, Field(lt=0x10000)]
type Proto = Literal['TCP', 'UDP']
type ServersTag = Annotated[
    str,
    Field(pattern=r'^[a-zA-Z\d_.-]+$')]

class StrUpperEnum(enum.StrEnum):

    @classmethod
    def _missing_(cls, value: Any) -> Self:
        return cls(str(value).upper())

class RdClass(enum.StrEnum):
    CH = 'CH'
    CS = 'CS'
    HESIOD = 'Hesiod'
    IN = 'IN'
    NONE = 'None'
    STAR = '*'

class Rcode(enum.StrEnum):
    FORMERR = 'FORMERR'
    NOERROR = 'NOERROR'
    NOTAUTH = 'NOTAUTH'
    NOTIMP = 'NOTIMP'
    NOTZONE = 'NOTZONE'
    NXDOMAIN = 'NXDOMAIN'
    NXRRSET = 'NXRRSET'
    REFUSED = 'REFUSED'
    SERVFAIL = 'SERVFAIL'
    YXDOMAIN = 'YXDOMAIN'
    YXRRSET = 'YXRRSET'

    def __index__(self) -> int:
        return getattr(RCODE, self, getattr(RCODE, self.SERVFAIL))

class RdType(StrUpperEnum):
    A = 'A'
    AAAA = 'AAAA'
    ANY = 'ANY'
    CNAME = 'CNAME'
    HTTPS = 'HTTPS'
    LOC = 'LOC'
    MX = 'MX'
    NS = 'NS'
    PTR = 'PTR'
    SOA = 'SOA'
    SRV = 'SRV'
    SVCB = 'SVCB'
    TXT = 'TXT'

class ErName(enum.StrEnum):
    NoNameservers = 'NoNameservers'
    Timeout = 'Timeout'

class BaseModel(pydantic.BaseModel):

    def generic_ordering(self, other: Self, comparator: Callable[[Self, Self], bool]) -> bool:
        attr = self.model_config.get('ordering_attribute')
        if attr and type(self) is type(other):
            return comparator(getattr(self, attr), getattr(other, attr))
        return NotImplemented

    def __lt__(self, other: Self) -> bool:
        return self.generic_ordering(other, operator.lt)

    def __gt__(self, other: Self) -> bool:
        return self.generic_ordering(other, operator.gt)

    def __lte__(self, other: Self) -> bool:
        return self.generic_ordering(other, operator.le)

    def __gte__(self, other: Self) -> bool:
        return self.generic_ordering(other, operator.ge)

class DataModel(BaseModel):

    def report(self, **kw) -> dict[str, Any]:
        kw.setdefault('context', {}).update(report=True)
        kw.setdefault('exclude_none', True)
        return self.model_dump(**kw)

    @model_serializer(mode='wrap')
    def report_serializer(self, handler: SerializerFunctionWrapHandler, info: SerializationInfo) -> dict[str, Any]:
        data: dict = handler(self)
        if info.context and info.context.get('report'):
            for key in self.model_config.get('report_exclude', ()):
                data.pop(key, None)
        return data

class Question(DataModel):
    "DNS question info"
    qname: str
    "The question name (domain)"
    rdtype: RdType = RdType.A
    "The record type requested"
    rdclass: RdClass = RdClass.IN
    "The query class"
    flags: NonNegativeInt = 0x100
    "The DNS flags value"

    @model_validator(mode='after')
    def autoreverse(self) -> Self:
        if self.rdtype is RdType.PTR and 'arpa' not in self.qname.lower():
            try:
                ip = ipaddress.ip_address(self.qname)
            except ValueError:
                pass
            else:
                self.qname = ip.reverse_pointer
        return self

class Response(DataModel):
    "DNS response info"
    id: NonNegativeInt = Field(lt=0x10000)
    "Query ID"
    server: Server
    "The server that responded"
    rtime: NonNegativeFloat
    "The response time"
    q: Question
    "The DNS question"
    code: Rcode
    "The response code (NOERROR, NXDOMAIN, SERVFAIL, etc.)"
    flags: NonNegativeInt = 0
    "The DNS flags value"
    rrset: Rset
    "The answer records returned"
    arset: Rset
    "Additional records returned"
    auset: Rset
    "Authority section"
    tag: ServersTag|None = None
    "The server group or rule tag name, for logging"
    failed: list[Server]|None = None
    "A list of servers that were tried & failed, if any"
    ername: ErName|None = None
    "Error name hint in case of SERVFAIL"

    @field_serializer('q', 'rrset', 'arset', 'auset', 'code', 'ername', mode='wrap')
    def _response_fields(self, value: Any, nxt: SerializerFunctionWrapHandler, info: FieldSerializationInfo):
        if info.context and info.context.get('report'):
            if isinstance(value, Question):
                return f'{value.rdclass} {value.rdtype} {value.qname}'
            if isinstance(value, list):
                return len(value)
        if isinstance(value, (Rcode, ErName)):
            return str(value)
        return nxt(value)

class BackendResponse(DataModel):
    id: NonNegativeInt = Field(lt=0x10000, default_factory=lambda: random.randrange(0x10000))
    "Query ID"
    code: Rcode = Rcode.NOERROR
    "The response code (NOERROR, NXDOMAIN, SERVFAIL, etc.)"
    flags: NonNegativeInt = 0
    "The DNS flags value"
    rrset: Rset = Field(default_factory=list)
    "The answer records returned"
    arset: Rset = Field(default_factory=list)
    "Additional records returned"
    auset: Rset = Field(default_factory=list)
    "Authority section"
    rtime: NonNegativeFloat = 0.0
    "The additional response time delay"
    ername: ErName|None = None
    "Error name hint in case of SERVFAIL"

class RunningMean(DataModel):
    """
    Track running mean
    """
    count: NonNegativeInt = 0
    'Total sample count'
    mean: NonNegativeFloat = 0.0
    'Running mean'
    model_config = ConfigDict(ordering_attribute='mean')

    def observe(self, value: NonNegativeFloat) -> None:
        'Update the running totals from the observed value'
        self.count += 1
        self.mean += (value - self.mean) / self.count

class RunningVariance(RunningMean):
    """
    Track running variance & standard deviation

    References:
    
    - Welford's online algorithm
      https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford%27s_online_algorithm

    - "Accurately computing running variance"
      https://www.johndcook.com/blog/standard_deviation/
    """
    delta_m2: NonNegativeFloat = 0.0
    'Aggregate of the squared distance from the mean'
    variance: NonNegativeFloat = 0.0
    'Running variance'
    stdev: NonNegativeFloat = 0.0
    'Running standard deviation'

    def observe(self, value: NonNegativeFloat) -> None:
        delta1 = value - self.mean
        super().observe(value)
        delta2 = value - self.mean
        self.delta_m2 += delta1 * delta2
        if self.count > 1:
            self.variance = self.delta_m2 / (self.count - 1)
            self.stdev = math.sqrt(self.variance)

class RunningRate(DataModel):
    """
    Sliding window rate per second
    """
    window: PositiveFloat = 5.0
    "Size of window in seconds"
    count: NonNegativeInt = 0
    cprev: NonNegativeInt = 0
    start: PositiveFloat = Field(default_factory=time.monotonic)

    def inc(self, i: int = 1) -> None:
        "Increment counter"
        self.count += i

    def val(self) -> NonNegativeFloat:
        "Current rate estimate"
        if (now := time.monotonic()) >= self.start + self.window:
            self.cprev, self.count, self.start = self.count, 0, now
        elapsed = now - self.start
        if elapsed < self.window:
            weight = (self.window - elapsed) / self.window
        else:
            weight = 0.0
        return (self.cprev * weight + self.count) / self.window

class DomainRule(DataModel):
    """
    Domain forwarding rule for resolver config
    """
    domain: Domain = Field(min_length=1, frozen=True)
    "The base domain"
    exclude: tuple[Domain, ...] = Field(default=(), frozen=True)
    "Subdomains to exclude"
    servers: tuple[Server, ...] = Field(min_length=1, frozen=True)
    "Non-empty list of servers"
    tag: ServersTag|None = None
    "Optional tag name of the servers group for logging"
    model_config = ConfigDict(ordering_attribute='order')

    def matches(self, qname: str) -> bool:
        "Whether the rule matches question (domain) name"
        return bool(
            self.inclpat.match(qname) and
            not self.exclpat.match(qname))

    @property
    def order(self) -> NegativeInt:
        return -len(self.domain)

    @cached_property
    def inclpat(self) -> re.Pattern:
        return self.buildpat(self.domain)

    @cached_property
    def exclpat(self) -> re.Pattern:
        return self.buildpat(*self.exclude)

    @classmethod
    def buildpat(cls, *domains: Domain) -> re.Pattern:
        if not domains:
            return re.compile(r'.^')
        ors = '|'.join(map(re.escape, domains))
        return re.compile(ors.join((r'^(.+\.)?(', r')\.?$')), re.I)

class Anomaly(DataModel):
    'Anomaly parameters'
    limit: NonNegativeInt|None = None
    'Number of total resolver queries to apply this anomaly'
    delayers: list[Delayer] = Field(default_factory=list)
    'List of delay configs'

class Delayer(DataModel):
    'Anomaly delayer parameters'
    pattern: Annotated[str, AfterValidator(lambda x: re.compile(x) and x)]
    'Server match pattern'
    delay: NonNegativeFloat = 0.0
    'The delay to apply'

class MockServer(DataModel):
    "Mock server parameters"
    r: PositiveFloat = 0.005
    'Base response time'
    v: NonNegativeFloat = 0.1
    'Volatility'

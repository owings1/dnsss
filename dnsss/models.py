from __future__ import annotations

import ipaddress
import math
import operator
import re
from functools import cached_property
from typing import Annotated, Any, Callable, Literal, Self

import pydantic
from pydantic import (AfterValidator, BeforeValidator, ConfigDict, Field,
                      IPvAnyAddress, NegativeInt, NonNegativeFloat,
                      NonNegativeInt, PlainSerializer, PositiveFloat,
                      PositiveInt, SerializationInfo,
                      SerializerFunctionWrapHandler, TypeAdapter,
                      ValidationError, field_serializer, model_serializer,
                      model_validator)

__all__ = [
    'AfterValidator',
    'Anomaly',
    'IPvAnyAddress',
    'BaseModel',
    'BeforeValidator',
    'ConfigDict',
    'Delayer',
    'DomainRule',
    'Field',
    'field_serializer',
    'MockServer',
    'model_serializer',
    'NonNegativeFloat',
    'NonNegativeInt',
    'PlainSerializer',
    'PositiveFloat',
    'PositiveInt',
    'Question',
    'Rcode',
    'RdType',
    'Response',
    'Rset',
    'RunningMean',
    'RunningVariance',
    'SerializationInfo',
    'SerializerFunctionWrapHandler',
    'Server',
    'ValidationError',
    'valnnf']

type Server = str
type Rcode = str
type Rset = list[str]
type RdType = Annotated[
    Literal['A', 'AAAA', 'CNAME', 'HTTPS', 'PTR', 'NS', 'TXT', 'MX', 'SOA', 'SRV', 'SVCB'],
    BeforeValidator(str.upper)]
type Domain = Annotated[
    str,
    AfterValidator(lambda x: x.strip('.').lower())]

NonNegFloatTa = TypeAdapter(NonNegativeFloat)

def valnnf(value: float) -> NonNegativeFloat:
    'Validate a NonNegativeFloat'
    return NonNegFloatTa.validate_python(value)

class BaseModel(pydantic.BaseModel):

    def report(self, **kw) -> dict[str, Any]:
        kw.setdefault('context', {}).update(terse=True)
        return self.model_dump(**kw)

    @model_serializer(mode='wrap')
    def terse_serializer(self, handler: SerializerFunctionWrapHandler, info: SerializationInfo) -> dict[str, Any]:
        data: dict = handler(self)
        if info.context and info.context.get('terse'):
            for key in self.model_config.get('terse_exclude', ()):
                data.pop(key, None)
        return data

    def generic_ordering(self, other: Self, comparator: Callable[[Self, Self], bool]):
        attr = self.model_config.get('ordering_attribute')
        if attr and type(self) is type(other):
            return comparator(getattr(self, attr), getattr(other, attr))
        return NotImplemented

    def __lt__(self, other: Self):
        return self.generic_ordering(other, operator.lt)

    def __gt__(self, other: Self):
        return self.generic_ordering(other, operator.gt)

    def __lte__(self, other: Self):
        return self.generic_ordering(other, operator.le)

    def __gte__(self, other: Self):
        return self.generic_ordering(other, operator.ge)

class Question(BaseModel):
    "DNS question info"
    qname: str
    "The question name (domain)"
    rdtype: RdType = 'A'
    "The record type requested"

    @model_validator(mode='after')
    def autoreverse(self) -> Self:
        if self.rdtype == 'PTR' and 'arpa' not in self.qname.lower():
            try:
                ip = ipaddress.ip_address(self.qname)
            except ValueError:
                pass
            else:
                self.qname = ip.reverse_pointer
        return self

class Response(BaseModel):
    "DNS response info"
    S: Server
    "The server that responded"
    R: NonNegativeFloat
    "The response time"
    q: Question
    "The DNS question"
    code: Rcode
    "The response code (NOERROR, NXDOMAIN, TIMEOUT, etc.)"
    rset: Rset
    "The records returned"
    failed: list[Server]|None = None
    "A list of servers that were tried & failed (TIMEOUT), if any"

    def report(self, **kw) -> dict[str, Any]:
        "Compact display data"
        kw.update(exclude_none=True)
        return super().report(**kw)|dict(
            q=f'{self.q.qname} {self.q.rdtype}',
            rset=len(self.rset))

class RunningMean(BaseModel):
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

class DomainRule(BaseModel):
    """
    Domain matching rule for resolver config
    """
    domain: Domain = Field(min_length=1, frozen=True)
    "The base domain"
    exclude: tuple[Domain, ...] = Field(default=(), frozen=True)
    "Subdomains to exclude"
    servers: list[Server] = Field(min_length=1)
    "Non-empty list of servers"
    model_config = ConfigDict(ordering_attribute='order')

    def matches(self, qname: str) -> bool:
        "Whether the rule matches question (domain) name"
        return bool(self.inclpat.match(qname) and not self.exclpat.match(qname))

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

class Anomaly(BaseModel):
    'Anomaaly parameters'
    limit: NonNegativeInt|None = None
    'Number of total resolver queries to apply this anomaly'
    delayers: list[Delayer] = Field(default_factory=list)
    'List of delay configs'

class Delayer(BaseModel):
    'Anomaaly delayer parameters'
    pattern: Annotated[str, AfterValidator(lambda x: re.compile(x) and x)]
    'Server match pattern'
    delay: NonNegativeFloat = 0.0
    'The delay to apply'

class MockServer(BaseModel):
    "Mock server parameters"
    r: PositiveFloat = 0.005
    'Base response time'
    v: NonNegativeFloat = 0.1
    'Volatility'

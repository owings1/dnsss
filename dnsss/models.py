from __future__ import annotations

import ipaddress
import math
import operator
import re
from typing import Annotated, Any, Callable, Literal, Self

import pydantic
from pydantic import (AfterValidator, BeforeValidator, ConfigDict, Field,
                      NegativeInt, NonNegativeFloat, NonNegativeInt,
                      PlainSerializer, PositiveFloat, PositiveInt,
                      SerializationInfo, SerializerFunctionWrapHandler,
                      TypeAdapter, ValidationError, field_serializer,
                      model_serializer, model_validator)

__all__ = [
    'AfterValidator',
    'Anomaly',
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
    'valnnf',
    'valpat']

type Server = str
type Rcode = str
type Rset = list[str]
type RdType = Annotated[
    Literal['A', 'AAAA', 'CNAME', 'PTR', 'NS', 'TXT', 'MX', 'SOA', 'SRV'],
    BeforeValidator(str.upper)]
type Domain = Annotated[
    str,
    AfterValidator(lambda x: x.strip('.').lower())]

NonNegFloatTa = TypeAdapter(NonNegativeFloat)

def valnnf(value: float) -> NonNegativeFloat:
    return NonNegFloatTa.validate_python(value)

def valpat(value: str) -> str:
    try:
        re.compile(value)
    except ValueError:
        raise ValidationError
    return value

class BaseModel(pydantic.BaseModel):

    def report(self, **kw) -> dict[str, Any]:
        kw.setdefault('context', {}).update(terse=True)
        return self.model_dump(**kw)

    @model_serializer(mode='wrap')
    def _ser(self, handler: SerializerFunctionWrapHandler, info: SerializationInfo) -> dict:
        data: dict = handler(self)
        if info.context and info.context.get('terse'):
            for key in self.model_config.get('terse_exclude', ()):
                data.pop(key, None)
        return data

    def __lt__(self, other: Self):
        return generic_ordering(operator.lt, self, other)

    def __gt__(self, other: Self):
        return generic_ordering(operator.gt, self, other)

    def __lte__(self, other: Self):
        return generic_ordering(operator.le, self, other)

    def __gte__(self, other: Self):
        return generic_ordering(operator.ge, self, other)

class DomainRule(BaseModel):
    domain: Domain = Field(min_length=1, frozen=True)
    servers: list[Server] = Field(min_length=1)
    exclude: list[Domain] = Field(default_factory=list)
    model_config = ConfigDict(ordering_attribute='order')

    @property
    def order(self) -> NegativeInt:
        return -len(self.domain)

    def matches(self, qname: str) -> bool:
        qname = qname.rstrip('.').lower()
        if qname == self.domain or qname.endswith(f'.{self.domain}'):
            for excl in self.exclude:
                if qname == excl or qname.endswith(f'.{excl}'):
                    break
            else:
                return True
        return False

class Response(BaseModel):
    S: Server
    R: NonNegativeFloat
    q: Question
    code: Rcode
    rset: Rset
    failed: list[Server]|None = None

    def report(self, **kw) -> dict[str, Any]:
        kw['exclude_none'] = True
        data = super().report(**kw)
        data['q'] = f'{self.q.qname} {self.q.rdtype}'
        data['rset'] = len(self.rset)
        return data

class MockServer(BaseModel):
    r: PositiveFloat = 0.005
    volatility: NonNegativeFloat = 0.1

class Delayer(BaseModel):
    pat: Annotated[str, AfterValidator(valpat)]
    delay: NonNegativeFloat = 0.0

class Anomaly(BaseModel):
    limit: NonNegativeInt|None = None
    delayers: list[Delayer] = Field(default_factory=list)

class Question(BaseModel):
    qname: str
    rdtype: RdType = 'A'

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

class RunningMean(BaseModel):
    count: NonNegativeInt = 0
    'Total sample count'
    mean: NonNegativeFloat = 0.0
    'Running mean'
    model_config = ConfigDict(ordering_attribute='mean')

    def observe(self, value: NonNegativeFloat) -> None:
        self.count += 1
        self.mean += (value - self.mean) / self.count

class RunningVariance(RunningMean):
    """
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

def generic_ordering[T: BaseModel](comparator: Callable[[T, T], bool], inst: T, other: T):
    attr = inst.model_config.get('ordering_attribute')
    if attr and type(inst) is type(other):
        return comparator(getattr(inst, attr), getattr(other, attr))
    return NotImplemented

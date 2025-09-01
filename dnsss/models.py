from __future__ import annotations

import ipaddress
import math
import re
from typing import Annotated, Literal, Self

import pydantic
from pydantic import (AfterValidator, BeforeValidator, Field,
                      NonNegativeFloat, NonNegativeInt, PlainSerializer,
                      ConfigDict,
                      PositiveFloat, PositiveInt, TypeAdapter, ValidationError,
                      model_serializer,SerializationInfo, SerializerFunctionWrapHandler,
                      field_serializer, model_validator)

__all__ = [
    'Anomaly',
    'Answer',
    'BaseModel',
    'BeforeValidator',
    'ConfigDict',
    'Delayer',
    'Field',
    'field_serializer',
    'model_serializer',
    'NonNegativeFloat',
    'NonNegativeInt',
    'PlainSerializer',
    'PositiveFloat',
    'PositiveInt',
    'Question',
    'RdType',
    'Response',
    'RunningMean',
    'RunningVariance',
    'SerializationInfo',
    'SerializerFunctionWrapHandler',
    'Server',
    'ValidationError',
    'valnnf',
    'valpat']

type Server = str
type Answer = list[str]
type RdType = Annotated[
    Literal['A', 'AAAA', 'CNAME', 'PTR', 'NS', 'TXT', 'MX', 'SOA', 'SRV'],
    BeforeValidator(str.upper)]

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
    @model_serializer(mode='wrap')
    def _ser(self, handler: SerializerFunctionWrapHandler, info: SerializationInfo) -> dict:
        data: dict = handler(self)
        if info.context and info.context.get('terse'):
            for key in self.model_config.get('terse_exclude', ()):
                data.pop(key, None)
        return data

class Response(BaseModel):
    S: Server
    R: NonNegativeFloat
    q: Question
    a: Answer

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

    def observe(self, value: NonNegativeFloat) -> None:
        self.count += 1
        self.mean += (value - self.mean) / self.count

    def __lt__(self, other: Self):
        if type(self) is type(other):
            return self.mean < other.mean
        return NotImplemented

    def __gt__(self, other: Self):
        if type(self) is type(other):
            return self.mean > other.mean
        return NotImplemented

    def __lte__(self, other: Self):
        if type(self) is type(other):
            return self.mean <= other.mean
        return NotImplemented

    def __gte__(self, other: Self):
        if type(self) is type(other):
            return self.mean >= other.mean
        return NotImplemented

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

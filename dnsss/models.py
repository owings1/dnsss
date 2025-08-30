from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta
from typing import Annotated, Literal, Self

from pydantic import (BaseModel, BeforeValidator, Field, NonNegativeFloat,
                      NonNegativeInt, PositiveFloat, PositiveInt, TypeAdapter,
                      ValidationError, model_validator)

__all__ = [
    'Anomaly',
    'Answer',
    'BaseModel',
    'BeforeValidator',
    'Field',
    'model_validator',
    'NonNegativeFloat',
    'NonNegativeInt',
    'PositiveFloat',
    'PositiveInt',
    'Question',
    'RdType',
    'Response',
    'RTime',
    'Server',
    'ValidationError',
    'valpat',
    'valrtime']

type Server = str
type RTime = NonNegativeFloat
type Answer = list[str]
type RdType = Annotated[
    Literal['A', 'AAAA', 'CNAME', 'PTR', 'NS', 'TXT', 'MX', 'SOA', 'SRV'],
    BeforeValidator(str.upper)]

valrtime = TypeAdapter(RTime).validate_python

def valpat(value: str) -> str:
    try:
        re.compile(value)
    except ValueError:
        raise ValidationError
    return value

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

    def begin(self) -> None:
        if not self.expiry:
            self.expiry = datetime.now() + timedelta(seconds=self.duration)

    def expired(self) -> bool:
        return bool(self.expiry) and datetime.now() > self.expiry
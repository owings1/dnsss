from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

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
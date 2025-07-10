from __future__ import annotations

import json
import logging
import random
import time
from argparse import ArgumentParser
from pathlib import Path
from typing import Any, ClassVar

import dns.resolver
import yaml
from pydantic import BaseModel, Field, NonNegativeFloat

from . import byvalue

logger = logging.getLogger('dnsss')

type Server = str
type RTime = NonNegativeFloat
type Answer = list[str]

class DataModel(BaseModel):
    pass

class BaseConfig(DataModel):
    servers: list[Server] = Field(default_factory=list, min_length=1)

class Question(DataModel):
    qname: str
    rdtype: str = 'A'

class Response(DataModel):
    S: Server
    R: RTime
    q: Question
    a: Answer

class BaseResolver:
    count: int = 0
    mean: RTime = 0.0

    def __init__(self, config: Any) -> None:
        config: BaseConfig = BaseConfig.model_validate(config)
        self.servers = config.servers
        self.Snext = list(self.servers)
        self.counts = dict.fromkeys(self.servers, 0)
        self.means = dict.fromkeys(self.servers, 0.0)
        self.lasts = dict.fromkeys(self.servers, 0.0)

    def adjust(self, S: Server, R: RTime) -> None:
        raise NotImplementedError

    def query(self, qname: str, rdtype: str = 'A') -> Response:
        q = dict(qname=qname, rdtype=rdtype.upper())
        S = random.choice(self.Snext)
        resolve = dns.resolver.make_resolver_at(S).resolve
        t = time.monotonic()
        try:
            rep = resolve(**q, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            rep = []
        finally:
            R = time.monotonic() - t
            self.adjust(S, R)
        self.mean = (self.mean * self.count + R) / (self.count + 1)
        self.count += 1
        self.means[S] = (self.means[S] * self.counts[S] + R) / (self.counts[S] + 1)
        self.counts[S] += 1
        self.lasts[S] = R
        return Response(S=S, R=R, q=q, a=[*map(str, rep)])

    def stateinfo(self) -> dict[str, Any]:
        return dict(
            count=self.count,
            counts=dict(sorted(self.counts.items(), key=byvalue, reverse=True)),
            mean=self.mean,
            means=dict(sorted(self.means.items(), key=byvalue)))

class BaseCommand:
    description: ClassVar[str] = ''
    resolver_class: ClassVar[type[BaseResolver]]
    default_config: ClassVar = dict(
        servers=[
            '8.8.8.8',
            '8.8.4.4',
            '1.1.1.1',
            '129.250.35.250',
            '208.67.222.222'])

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = ArgumentParser(description=cls.description)
        cls.add_arguments(parser)
        return parser

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        arg = parser.add_argument
        arg('qname', help='Hostname to query')
        arg('rdtype', nargs='?', default='A', help='Record type, default A')
        arg('--file', '-f', type=Path, help='Path to yaml config file')
        arg('--interval', '-n', type=float, help='Poll interval, for non-interactive mode')
        arg('--count', '-c', type=int, help='Number of queries after which to quit')

    @classmethod
    def main(cls):
        parser = cls.create_parser()
        opts = parser.parse_args()
        command = cls(parser, opts)
        command.run()

    def __init__(self, parser: ArgumentParser, opts):
        self.parser = parser
        self.opts = opts

    def run(self) -> None:
        q = Question(**vars(self.opts)).model_dump()
        if self.opts.file:
            with open(self.opts.file) as file:
                config = yaml.safe_load(file)
        else:
            config = self.default_config
        resolver = self.resolver_class(config)
        try:
            i = 0
            while True:
                try:
                    rep = resolver.query(**q)
                except:
                    logger.exception(f'Query failed')
                else:
                    info = rep.model_dump(mode='json') | resolver.stateinfo()
                    print(json.dumps(info, indent=2), flush=True)
                if self.opts.interval:
                    time.sleep(self.opts.interval)
                else:
                    input()
                i += 1
                if self.opts.count and i >= self.opts.count:
                    break
        except (EOFError, KeyboardInterrupt):
            pass
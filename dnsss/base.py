from __future__ import annotations

import json
import logging
import random
import time
from argparse import ArgumentParser
from pathlib import Path
from typing import Annotated, Any, ClassVar, Literal, Sequence

import dns.resolver
import yaml
from pydantic import (BaseModel, BeforeValidator, Field, NonNegativeFloat,
                      NonNegativeInt, PositiveFloat, PositiveInt)

from . import addmean, byvalue

logger = logging.getLogger('dnsss')

type Server = str
type RTime = NonNegativeFloat
type Answer = list[str]
type RdType = Annotated[
    Literal['A', 'AAAA', 'CNAME', 'PTR', 'NS', 'TXT', 'MX', 'SOA', 'SRV'],
    BeforeValidator(str.upper)]

class DataModel(BaseModel):
    pass

class Question(DataModel):
    qname: str
    rdtype: RdType = 'A'

class Response(DataModel):
    S: Server
    R: RTime
    q: Question
    a: Answer

class BaseResolver:

    class Params(DataModel):
        pass

    class Config(DataModel):
        servers: list[Server] = Field(min_length=2)
        params: BaseResolver.Params
        tcp: bool = False

    servers: list[Server]
    params: BaseResolver.Params
    tcp: bool
    count: NonNegativeInt
    counts: dict[Server, NonNegativeInt]
    mean: RTime
    means: dict[Server, RTime]

    def __init__(self, config: Any) -> None:
        config: BaseResolver.Config = self.Config.model_validate(config)
        self.servers = config.servers
        self.params = config.params
        self.tcp = config.tcp
        self.count = 0
        self.mean = 0.0
        self.counts = dict.fromkeys(self.servers, 0)
        self.means = dict.fromkeys(self.servers, 0.0)

    def adjust(self, S: Server, R: RTime) -> None:
        self.count += 1
        self.counts[S] += 1
        self.mean = addmean(R, self.mean, self.count)
        self.means[S] = addmean(R, self.means[S], self.counts[S])

    def select(self) -> Server:
        return random.choice(self.servers)

    def query(self, qname: str, rdtype: RdType = 'A') -> Response:
        q = Question(qname=qname, rdtype=rdtype)
        S = self.select()
        resolve = dns.resolver.make_resolver_at(S).resolve
        t = time.monotonic()
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
        self.count = state['count']
        self.mean = state['mean']
        self.counts = state['counts']
        self.means = state['means']

class BaseCommand:
    description: ClassVar[str] = ''
    resolver_class: ClassVar[type[BaseResolver]]
    termerrors: ClassVar[tuple[type[Exception], ...]] = (
        EOFError,
        KeyboardInterrupt,
        BrokenPipeError)

    class Options(BaseModel):
        qname: str
        rdtype: RdType
        file: Path
        interval: PositiveFloat|None
        count: PositiveInt|None
        load: Path|None

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = ArgumentParser(description=cls.description)
        cls.add_arguments(parser)
        return parser

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        arg = parser.add_argument
        confdefault = Path(__file__).resolve().parent.parent/'config.example.yml'
        arg('qname', help='Hostname to query')
        arg('rdtype', nargs='?', default='A', help='Record type, default A')
        arg('--file', '-f', default=confdefault, help='Path to yaml config file')
        arg('--interval', '-n', help='Poll interval, for non-interactive mode')
        arg('--count', '-c', help='Number of queries after which to quit')
        arg('--load', '-l', help='State file to load')

    @classmethod
    def main(cls, args: Sequence[str]|None = None) -> None:
        parser = cls.create_parser()
        cls(parser, parser.parse_args(args)).run()

    def __init__(self, parser: ArgumentParser, opts: Any) -> None:
        self.parser = parser
        self.opts = self.Options.model_validate(opts, from_attributes=True)

    def setup(self) -> None:
        self.q = Question.model_validate(self.opts, from_attributes=True)
        with self.opts.file.open() as file:
            config = yaml.safe_load(file)
        self.resolver = self.resolver_class(config)
        if self.opts.load:
            with self.opts.load.open() as file:
                self.resolver.load(yaml.safe_load(file))

    def run(self) -> None:
        self.setup()
        self.report(self.resolver.state())
        try:
            while True:
                self.loop()
                if self.opts.count and self.resolver.count >= self.opts.count:
                    break
        except self.termerrors:
            pass

    def loop(self) -> None:
        try:
            rep = self.resolver.query(**self.q.model_dump())
        except self.termerrors:
            raise
        except:
            logger.exception(f'Query failed')
        else:
            self.report(rep.model_dump() | self.resolver.state())
        if self.opts.interval:
            time.sleep(self.opts.interval)
        else:
            input()

    def report(self, info: Any) -> None:
        print(json.dumps(info, indent=2), end=None, flush=True)

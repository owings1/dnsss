from __future__ import annotations

import json
import logging
import random
import time
from argparse import ArgumentParser
from pathlib import Path
from typing import Any

import dns.resolver
import yaml
from pydantic import BaseModel, Field, NonNegativeFloat, PositiveFloat

logger = logging.getLogger('dnsss')

type Server = str
type RTime = NonNegativeFloat
type Answer = list[str]

class DataModel(BaseModel):
    pass

class Config(DataModel):
    servers: list[Server] = Field(default_factory=list, min_length=1)
    initial: PositiveFloat = 0.05
    params: tuple[PositiveFloat, PositiveFloat] = (0.7, 0.98)

class Question(DataModel):
    qname: str
    rdtype: str = 'A'

class Response(DataModel):
    S: Server
    R: RTime
    q: Question
    a: Answer

class Resolver:
    count: int = 0
    mean: float = 0.0

    def __init__(self, config: Any) -> None:
        config: Config = Config.model_validate(config)
        self.params = config.params
        self.SR = dict.fromkeys(config.servers, config.initial)
        self.Snext = list(self.SR)
        self.counts = dict.fromkeys(self.SR, 0)
        self.means = dict.fromkeys(self.SR, 0.0)

    def adjust(self, S: Server, R: float) -> None:
        a, g = self.params
        lo = None
        for Si, Ri in self.SR.items():
            if Si == S:
                r = a * Ri + (1 - a) * R
            else:
                r = g * Ri
            if lo is None or r < lo:
                lo = r
                self.Snext = [Si]
            elif r == lo:
                self.Snext.append(Si)
            self.SR[Si] = r

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
        return Response(S=S, R=R, q=q, a=[*map(str, rep)])

def main():
    parser = ArgumentParser(description='Bind algorithm demo')
    arg = parser.add_argument
    arg('qname', help='Hostname to query')
    arg('rdtype', nargs='?', default='A', help='Record type, default A')
    arg('--file', '-f', type=Path, help='Path to yaml config file')
    arg('--interval', '-n', type=float, help='Poll interval, for non-interactive mode')
    arg('--count', '-c', type=int, help='Number of queries after which to quit')
    opts = parser.parse_args()
    q = Question(**vars(opts)).model_dump()
    if opts.file:
        with open(opts.file) as file:
            config = Config(**yaml.safe_load(file))
    else:
        config = Config(
            servers=[
                '8.8.8.8',
                '8.8.4.4',
                '1.1.1.1',
                '129.250.35.250',
                '208.67.222.222'])
    resolver = Resolver(config)
    try:
        i = 0
        while True:
            try:
                rep = resolver.query(**q)
            except:
                logger.exception(f'Query failed')
            else:
                info = dict(
                    **rep.model_dump(mode='json'),
                    SR=dict(sorted(resolver.SR.items(), key=byvalue)),
                    count=resolver.count,
                    counts=dict(sorted(
                        resolver.counts.items(),
                        key=byvalue,
                        reverse=True)),
                    mean=resolver.mean,
                    means=dict(sorted(resolver.means.items(), key=byvalue)))
                print(json.dumps(info, indent=2), flush=True)
            if opts.interval:
                time.sleep(opts.interval)
            else:
                input()
            i += 1
            if opts.count and i >= opts.count:
                break
    except (EOFError, KeyboardInterrupt):
        pass

def byvalue[T](item: tuple[Any, T]) -> T:
    return item[1]

if __name__ == '__main__':
    main()
from __future__ import annotations

import enum
import json
import logging
import random
import re
import sys
import termios
import time
import tty
from argparse import ArgumentParser, Namespace
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from select import select
from typing import (Annotated, Any, ClassVar, Generator, Iterable, Iterator,
                    Sequence)

import yaml

from .algs import registry
from .models import *

BASEDIR = Path(__file__).resolve().parent.parent
DEFAULT_ALG = 'bind'
DEFAULT_FORMAT = 'table'
DEFAULT_QNAME = 'google.com'
DEFAULT_TABLEFMT = 'simple'
INTERVAL_MAX = 300.0
INTERVAL_MIN = 0.001
INTERVAL_STEP = 1.5
INTERVAL_START = 1.0
SELECT_TIMEOUT = 0.01
logger = logging.getLogger('dnsss')

class CommandOptions(BaseModel):
    model_config = ConfigDict(from_attributes=True)

class BaseCommand[O: CommandOptions]:
    prog: ClassVar[str|None] = None
    description: ClassVar[str|None] = None
    options_model: ClassVar[type[O]] = CommandOptions

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        pass

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = ArgumentParser(description=cls.description, prog=cls.prog)
        cls.add_arguments(parser)
        return parser

    @classmethod
    def main(cls, args: Sequence[str]|None = None) -> None:
        parser = cls.create_parser()
        cls(parser, parser.parse_args(args)).run()

    def __init__(self, parser: ArgumentParser, opts: Namespace) -> None:
        self.parser = parser
        self.opts = self.options_model.model_validate(opts)

    def run(self) -> None: ...

def valalg(alg: str) -> str:
    alg = alg.lower()
    if alg in registry:
        return alg
    raise ValidationError('Invalid algorithm')

class UserQuit(Exception):
    pass

class UserContinue(Exception):
    pass

class OutFormat(enum.StrEnum):
    json = 'json'
    yaml = 'yaml'
    table = 'table'

class MainOptions(CommandOptions):
    alg: Annotated[str, BeforeValidator(valalg)] = DEFAULT_ALG
    config: Path|None = None
    interval: NonNegativeFloat = 0.0
    count: NonNegativeInt = 0
    output: Path|None = None
    load: Path|None = None
    save: bool = False
    format: OutFormat = DEFAULT_FORMAT
    tablefmt: str = DEFAULT_TABLEFMT

class MainCommand(BaseCommand[MainOptions]):
    prog: ClassVar = 'dnsss'
    options_model: ClassVar = MainOptions
    termerrors: ClassVar[tuple[type[Exception], ...]] = (
        EOFError,
        KeyboardInterrupt,
        BrokenPipeError,
        UserQuit)

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        super().add_arguments(parser)
        arg = parser.add_argument
        defaults = cls.options_model()
        arg(
            '--alg', '-a',
            default=defaults.alg,
            type=valalg,
            choices=list(registry),
            help='Resolver algorithm')
        arg(
            '--config', '-f',
            default=defaults.config,
            help='Path to YAML config file')
        arg(
            '--interval', '-n',
            default=defaults.interval,
            help='Poll interval')
        arg(
            '--count', '-c',
            default=defaults.count,
            help='Number of queries after which to quit')
        arg(
            '--output', '-o',
            default=...,
            help='File to write state on save')
        arg(
            '--save', '-s',
            action='store_true',
            help='Save state file automatically')
        arg(
            '--load', '-l',
            nargs='?',
            default=...,
            help='Load state from file')
        arg(
            '--format', '-F',
            default=defaults.format,
            choices=OutFormat,
            help=f'Output format, default {defaults.format}')

    def __init__(self, parser: ArgumentParser, opts: Namespace) -> None:
        alg = valalg(opts.alg)
        if opts.output is ...:
            opts.output = f'state.{alg}.yml'
        if opts.load is ...:
            opts.load = None
        elif opts.load is None:
            opts.load = opts.output
        super().__init__(parser, opts)
        self.keyaction = KeyAction(self)
        self.stdin = sys.stdin
        self.stdout = sys.stdout
        self.paused = False
        self.count = 0
        self.anomaly: Anomaly|None = None

    def run(self) -> None:
        self.setup()
        with self.ttycontext():
            table = self.opts.format == 'table' and self.opts.tablefmt
            self.report(state=self.resolver.state.report(table=table))
            if self.stdin.isatty():
                tty.setcbreak(self.stdin.fileno())
            try:
                while True:
                    self.loop()
            except self.termerrors:
                pass

    def setup(self) -> None:
        self.tcorgattr = self.stdin.isatty() and termios.tcgetattr(self.stdin.fileno())
        if self.opts.config:
            cwd = self.opts.config.parent
            with self.opts.config.open() as file:
                config = yaml.safe_load(file)
        else:
            cwd = Path('.')
            config = {}
        qentries = (
            config.pop('questions', None) or [DEFAULT_QNAME])
        self.questions = list(resolve_questions(qentries, cwd))
        self.anomalies = deque(
            map(Anomaly.model_validate, config.pop('anomalies', [])))
        self.resolver = registry[self.opts.alg](config=config)
        if self.opts.load:
            with self.opts.load.open() as file:
                self.resolver.state.load(yaml.safe_load(file))

    def loop(self) -> None:
        self.prep_anomaly()
        if self.stdin.isatty():
            try:
                self.readtty()
            except UserContinue:
                pass
        else:
            time.sleep(self.opts.interval or INTERVAL_START)
        q = random.choice(self.questions)
        try:
            rep = self.resolver.query(q)
        except self.termerrors:
            raise
        except:
            logger.exception(f'Query failed')
        else:
            report = dict(query=rep.report())
            if self.anomaly:
                if self.anomaly.limit is not None:
                    self.anomaly.limit -= 1
                report.update(anomaly=self.anomaly.model_dump())
            table = self.opts.format == 'table' and self.opts.tablefmt
            state = self.resolver.state.report(table=table)
            report.update(state=state)
            self.report(report)
        finally:
            if self.opts.save:
                self.save()
        self.count += 1
        if self.count >= self.opts.count > 0:
            raise UserQuit

    def prep_anomaly(self) -> None:
        while True:
            if self.anomaly and (
                self.anomaly.limit is None or
                self.anomaly.limit > 0):
                self.resolver.delayers = self.anomaly.delayers
                break
            if self.anomalies:
                self.anomaly = self.anomalies.popleft()
                continue
            self.anomaly = None
            self.resolver.delayers = []
            break

    def readtty(self) -> None:
        start = time.monotonic()
        sargs = ([self.stdin.fileno()], [], [], SELECT_TIMEOUT)
        while True:
            if select(*sargs)[0]:
                key = self.stdin.read(1).upper()
                self.keyaction(key)
            t = time.monotonic() - start
            if not self.paused and 0 < self.opts.interval < t:
                raise UserContinue

    def save(self) -> None:
        with self.opts.output.open('w') as file:
            yaml.safe_dump(self.resolver.state.model_dump(), file, sort_keys=False)

    def report(self, *args, **kw) -> None:
        info = dict(*args, **kw)
        stdout = self.stdout
        if self.opts.format == 'json':
            json.dump(info, stdout, indent=2)
            stdout.write('\n')
        elif self.opts.format in ('yaml', 'table'):
            yaml.dump(info, stdout, sort_keys=False, width=float('inf'))
            stdout.write('\n---\n')
            if not stdout.isatty():
                # Piping to yq needs this
                stdout.write('---\n---\n')
        else:
            raise NotImplementedError
        stdout.flush()

    @contextmanager
    def ttycontext(self, when: int = termios.TCSADRAIN) -> Generator[None]:
        if not self.stdin.isatty():
            yield
            return
        fdin = self.stdin.fileno()
        tcattr = termios.tcgetattr(fdin)
        try:
            yield
        finally:
            termios.tcsetattr(fdin, when, tcattr)

class KeyAction:
    keymap: ClassVar[dict[str, str]] = {
        '\n': 'continue',
        'Q': 'quit',
        'S': 'save',
        'P': 'pause',
        'I': 'interval',
        'A': 'anomaly',
        '+': 'faster',
        '-': 'slower',
        '?': 'help'}

    def __init__(self, cmd: MainCommand) -> None:
        self.cmd = cmd

    def __call__(self, key: str) -> None:
        if key in self.keymap:
            getattr(self, f'cmd_{self.keymap[key]}')()

    def cmd_continue(self) -> None:
        raise UserContinue

    def cmd_quit(self) -> None:
        raise UserQuit

    def cmd_save(self) -> None:
        cmd = self.cmd
        cmd.save()
        cmd.report(save=cmd.opts.output.name)

    def cmd_pause(self) -> None:
        cmd = self.cmd
        if cmd.opts.interval:
            cmd.paused = not cmd.paused
            cmd.report(paused=cmd.paused)

    def cmd_interval(self) -> None:
        cmd = self.cmd
        opt = self.input('Set interval')
        try:
            interval = valnnf(opt or cmd.opts.interval)
        except ValidationError as err:
            cmd.report(error=str(err))
        else:
            if interval:
                interval = min(INTERVAL_MAX, max(INTERVAL_MIN, interval))
            cmd.opts.interval = interval
            cmd.report(interval=interval)

    def cmd_anomaly(self) -> None:
        cmd = self.cmd
        opt = self.input('Set anomaly: <pat>/<delay>[/[limit]]')
        if opt:
            parts = opt.removesuffix('/').split('/')
            if len(parts) == 2:
                parts.append(None)
            try:
                pat, delay, limit = parts
                anomaly = Anomaly(
                    limit=limit,
                    delayers=[dict(pat=pat, delay=delay)])
            except ValueError as err:
                cmd.report(error=str(err))
                return
            else:
                cmd.report(anomaly=anomaly.model_dump())
        else:
            anomaly = None
            cmd.report(anomaly=anomaly)
        cmd.anomaly = anomaly
        cmd.prep_anomaly()

    def cmd_faster(self) -> None:
        cmd = self.cmd
        if cmd.opts.interval:
            cmd.opts.interval = max(
                INTERVAL_MIN,
                cmd.opts.interval / INTERVAL_STEP)
        else:
            cmd.opts.interval = INTERVAL_START
        cmd.report(interval=cmd.opts.interval)

    def cmd_slower(self) -> None:
        cmd = self.cmd
        cmd.opts.interval = min(
            INTERVAL_MAX,
            cmd.opts.interval * INTERVAL_STEP)
        cmd.report(interval=cmd.opts.interval)

    def cmd_help(self) -> None:
        self.cmd.report(help={
            key.replace('\n', '[enter]'): value
            for key, value in self.keymap.items()})

    def input(self, prompt: str|None = None) -> str:
        cmd = self.cmd
        if prompt:
            cmd.report(prompt=prompt)
        stdin = cmd.stdin
        with cmd.ttycontext():
            if stdin.isatty():
                termios.tcsetattr(stdin.fileno(), termios.TCSANOW, cmd.tcorgattr)
            return stdin.readline().strip()

def resolve_questions(entries: Iterable[Any], cwd: Path) -> Iterator[Question]:
    qkeys = ('qname', 'rdtype')
    pat = re.compile(r'^([^#].*[^\s])')
    for qraw in entries:
        if isinstance(qraw, str) and qraw.startswith('@'):
            with cwd.joinpath(qraw[1:]).open() as file:
                it = filter(pat.match, file.readlines())
                it = map(str.rstrip, it)
        else:
            it = [qraw]
        for qstr in it:
            qvals = (qstr.split(maxsplit=1) + ['A'])[:2]
            yield Question.model_validate(dict(zip(qkeys, qvals)))

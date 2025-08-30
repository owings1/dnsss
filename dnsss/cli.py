from __future__ import annotations

import json
import logging
import random
import sys
import termios
import time
import tty
from argparse import ArgumentParser, Namespace
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from select import select
from typing import Annotated, ClassVar, Sequence

import yaml

from .algs import registry
from .models import *
from .utils import linefilter

BASEDIR = Path(__file__).resolve().parent.parent
DEFAULT_ALG = 'bind'
DEFAULT_CONFIG = BASEDIR/'config.example.yml'
DEFAULT_QNAME = 'google.com'
INTERVAL_MAX = 300.0
INTERVAL_MIN = 0.001
SELECT_TIMEOUT = 0.01
logger = logging.getLogger('dnsss')

class CommandOptions(BaseModel):
    model_config: ClassVar = dict(from_attributes=True)

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

class MainOptions(CommandOptions):
    alg: Annotated[str, BeforeValidator(valalg)] = DEFAULT_ALG
    config: Path = DEFAULT_CONFIG
    interval: RTime = 0.0
    count: NonNegativeInt = 0
    output: Path|None = None
    load: Path|None = None
    yaml: bool = False
    save: bool = False

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
        arg('--alg', '-a', default=defaults.alg, type=valalg, choices=list(registry), help='Resolver algorithm')
        arg('--config', '-f', default=defaults.config, help='Path to YAML config file')
        arg('--interval', '-n', default=defaults.interval, help='Poll interval')
        arg('--count', '-c', default=defaults.count, help='Number of queries after which to quit')
        arg('--output', '-o', default=..., help='File to write state on save')
        arg('--save', '-s', action='store_true', help='Save state file automatically')
        arg('--load', '-l', nargs='?', default=..., help='Load state from file')
        arg('--yaml', action='store_true', help='Print YAML')

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

    def run(self) -> None:
        self.setup()
        with self.ttycontext():
            self.report(self.resolver.state())
            if self.stdin.isatty():
                tty.setcbreak(self.stdin.fileno())
            try:
                while True:
                    self.loop()
            except self.termerrors:
                pass

    def setup(self) -> None:
        self.tcorgattr = self.stdin.isatty() and termios.tcgetattr(self.stdin.fileno())
        with self.opts.config.open() as file:
            config = yaml.safe_load(file)
        qraws = isinstance(config, dict) and config.pop('questions', None) or [DEFAULT_QNAME]
        qstrs: deque[str] = deque()
        for qraw in qraws:
            if isinstance(qraw, str) and qraw.startswith('@'):
                qfile = Path(self.opts.config.parent, qraw[1:])
                with qfile.open() as file:
                    qstrs.extend(map(str.rstrip, filter(linefilter, file.readlines())))
            else:
                qstrs.append(qraw)
        qargs = ((qstr.split(maxsplit=1) + ['A'])[:2] for qstr in qstrs)
        self.questions = [
            Question(qname=qname, rdtype=rdtype)
            for qname, rdtype in qargs]
        self.resolver = registry[self.opts.alg](config)
        if self.opts.load:
            with self.opts.load.open() as file:
                self.resolver.load(yaml.safe_load(file))

    def loop(self) -> None:
        if self.stdin.isatty():
            try:
                self.readtty()
            except UserContinue:
                pass
        else:
            time.sleep(self.opts.interval or 1)
        q = random.choice(self.questions)
        try:
            rep = self.resolver.query(q)
        except self.termerrors:
            raise
        except:
            logger.exception(f'Query failed')
        else:
            self.report(rep.model_dump() | self.resolver.state(terse=True))
        finally:
            if self.opts.save:
                self.save()
        self.count += 1
        if self.count >= self.opts.count > 0:
            raise UserQuit

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
            yaml.safe_dump(self.resolver.state(), file, sort_keys=False)

    def report(self, *args, **kw) -> None:
        info = dict(*args, **kw)
        stdout = self.stdout
        if self.opts.yaml:
            yaml.safe_dump(info, stdout, sort_keys=False)
            stdout.write('\n---\n')
            if not stdout.isatty():
                # Piping to yq needs this
                stdout.write('---\n---\n')
        else:
            json.dump(info, stdout, indent=2)
            stdout.write('\n')
        stdout.flush()

    @contextmanager
    def ttycontext(self, when: int = termios.TCSADRAIN):
        fdin = self.stdin.fileno()
        tcattr = self.stdin.isatty() and termios.tcgetattr(fdin)
        try:
            yield
        finally:
            if tcattr:
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
            interval = valrtime(opt or cmd.opts.interval)
        except ValidationError as err:
            cmd.report(error=str(err))
        else:
            if interval:
                interval = min(INTERVAL_MAX, max(INTERVAL_MIN, interval))
            cmd.opts.interval = interval
            cmd.report(interval=interval)

    def cmd_anomaly(self) -> None:
        cmd = self.cmd
        opt = self.input('Set anomaly <pat>/<delay>/<duration>')
        if opt:
            try:
                pat, delay, duration = opt.split('/')
                anomaly = Anomaly(
                    pat=pat,
                    delay=delay,
                    duration=duration)
            except (ValueError, ValidationError) as err:
                cmd.report(error=str(err))
                return
            else:
                anomdata = anomaly.model_dump(mode='json', exclude=['expiry'])
                cmd.report(anomaly=anomdata)
        else:
            anomaly = None
            cmd.report(anomaly=anomaly)
        cmd.resolver.anomaly = anomaly

    def cmd_faster(self) -> None:
        cmd = self.cmd
        if cmd.opts.interval:
            cmd.opts.interval = max(INTERVAL_MIN, cmd.opts.interval / 1.5)
        else:
            cmd.opts.interval = 1.0
        cmd.report(interval=cmd.opts.interval)

    def cmd_slower(self) -> None:
        cmd = self.cmd
        cmd.opts.interval = min(INTERVAL_MAX, cmd.opts.interval * 1.5)
        cmd.report(interval=cmd.opts.interval)

    def cmd_help(self) -> None:
        cmd = self.cmd
        cmd.report(help={
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

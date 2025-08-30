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
from typing import Annotated, Any, ClassVar, Sequence

import yaml

from .models import *
from .algs import registry

SELECT_TIMEOUT = 0.01
DEFAULT_ALG = 'bind'
DEFAULT_QNAME = 'google.com'
INTERVAL_MAX = 300.0
INTERVAL_MIN = 0.001
logger = logging.getLogger('dnsss')

def valalg(alg: str) -> str:
    alg = alg.lower()
    if alg in registry:
        return alg
    raise ValidationError('Invalid algorithm')

class UserQuit(Exception):
    pass

class UserContinue(Exception):
    pass

class MainCommand:
    prog: ClassVar[str] = 'dnsss'
    description: ClassVar[str] = ''
    termerrors: ClassVar[tuple[type[Exception], ...]] = (
        EOFError,
        KeyboardInterrupt,
        BrokenPipeError,
        UserQuit)

    class Options(BaseModel):
        alg: Annotated[str, BeforeValidator(valalg)] = DEFAULT_ALG
        config: Path = Path(__file__).resolve().parent.parent/'config.example.yml'
        interval: RTime = 0.0
        count: NonNegativeInt = 0
        output: Path = ...
        load: Path|None = ...
        yaml: bool = False
        save: bool = False

        @model_validator(mode='wrap')
        @classmethod
        def _fillpaths(cls, obj: Any, handler):
            if isinstance(obj, Namespace):
                data = vars(obj)
            elif isinstance(obj, BaseModel):
                data = obj.model_dump()
            else:
                data = dict(obj)
            alg = valalg(data.get('alg', DEFAULT_ALG))
            if data.get('output', ...) is ...:
                data['output'] = f'state.{alg}.yml'
            if data.get('load', ...) is ...:
                data['load'] = None
            elif data.get('load', ...) is None:
                data['load'] = data.get('output')
            return handler(data)

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = ArgumentParser(description=cls.description, prog=cls.prog)
        cls.add_arguments(parser)
        return parser

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        arg = parser.add_argument
        defaults = cls.Options()
        arg('--alg', '-a', default=defaults.alg, type=str.lower, choices=list(registry), help='Resolver algorithm')
        arg('--config', '-f', default=defaults.config, help='Path to YAML config file')
        arg('--interval', '-n', default=defaults.interval, help='Poll interval')
        arg('--count', '-c', default=defaults.count, help='Number of queries after which to quit')
        arg('--output', '-o', default=..., help='File to write state on save')
        arg('--save', '-s', action='store_true', help='Save state file automatically')
        arg('--load', '-l', nargs='?', default=..., help='Load state from file')
        arg('--yaml', action='store_true', help='Print YAML')

    @classmethod
    def main(cls, args: Sequence[str]|None = None) -> None:
        parser = cls.create_parser()
        cls(parser, parser.parse_args(args)).run()

    def __init__(self, parser: ArgumentParser, opts: Any) -> None:
        self.parser = parser
        self.opts = self.Options.model_validate(opts)
        self.keyaction = KeyAction(self)
        self.stdin = sys.stdin
        self.stdout = sys.stdout
        self.paused = False
        self.delay = 0.0
        self.count = 0

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

    @contextmanager
    def ttycontext(self, when: int = termios.TCSADRAIN):
        fdin = self.stdin.fileno()
        tcattr = self.stdin.isatty() and termios.tcgetattr(fdin)
        try:
            yield
        finally:
            if tcattr:
                termios.tcsetattr(fdin, when, tcattr)

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

    def loop(self) -> None:
        self.delay = 0.0
        if self.stdin.isatty():
            try:
                self.readtty()
            except UserContinue:
                pass
        else:
            time.sleep(self.opts.interval or 1)
        q = random.choice(self.questions)
        try:
            rep = self.resolver.query(**q.model_dump(), delay=self.delay)
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

class KeyAction:
    keymap: ClassVar[dict[str, str]] = {
        '\n': 'continue',
        'Q': 'quit',
        'S': 'save',
        'P': 'pause',
        'D': 'delay',
        'I': 'interval',
        'A': 'anomaly',
        '+': 'faster',
        '-': 'slower',
        '?': 'help'}

    def __init__(self, cmd: MainCommand) -> None:
        self.cmd = cmd

    def __call__(self, key: str) -> None:
        if key in self.keymap:
            getattr(self, f'cmd_{self.keymap[key]}')(self.cmd)

    def cmd_continue(self, cmd: MainCommand) -> None:
        raise UserContinue

    def cmd_quit(self, cmd: MainCommand) -> None:
        raise UserQuit

    def cmd_save(self, cmd: MainCommand) -> None:
        cmd.save()
        cmd.report(save=cmd.opts.output.name)

    def cmd_pause(self, cmd: MainCommand) -> None:
        if cmd.opts.interval:
            cmd.paused = not cmd.paused
            cmd.report(paused=cmd.paused)

    def cmd_delay(self, cmd: MainCommand) -> None:
        opt = self.input('Delay for next query')
        try:
            cmd.delay = valrtime(opt or 0)
        except ValidationError as err:
            cmd.report(error=str(err))
            cmd.delay = 0.0
        cmd.report(delay=cmd.delay)

    def cmd_interval(self, cmd: MainCommand) -> None:
        opt = self.input('Set interval')
        try:
            interval = valrtime(opt or cmd.opts.interval)
        except ValidationError as err:
            cmd.report(error=str(err))
        else:
            if interval:
                interval = min(300.0, max(0.001, interval))
            cmd.opts.interval = interval
            cmd.report(interval=interval)

    def cmd_anomaly(self, cmd: MainCommand) -> None:
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

    def cmd_faster(self, cmd: MainCommand) -> None:
        if cmd.opts.interval:
            cmd.opts.interval = max(INTERVAL_MIN, cmd.opts.interval / 1.5)
        else:
            cmd.opts.interval = 1.0
        cmd.report(interval=cmd.opts.interval)

    def cmd_slower(self, cmd: MainCommand) -> None:
        cmd.opts.interval = min(INTERVAL_MAX, cmd.opts.interval * 1.5)
        cmd.report(interval=cmd.opts.interval)

    def cmd_help(self, cmd: MainCommand) -> None:
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

def linefilter(line: str) -> bool:
    return bool(line.strip()) and not line.startswith('#')

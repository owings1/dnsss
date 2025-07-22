from __future__ import annotations

import json
import logging
import sys
import termios
import time
import tty
from argparse import ArgumentParser
from contextlib import contextmanager
from pathlib import Path
from select import select
from typing import Any, ClassVar, Sequence

import yaml
from pydantic import BaseModel, NonNegativeInt, ValidationError

from .base import Anomaly, BaseResolver, Question, RdType, RTime, valrtime

logger = logging.getLogger('dnsss')

class UserQuit(Exception):
    pass

class UserContinue(Exception):
    pass

class BaseCommand:
    description: ClassVar[str] = ''
    slug: ClassVar[str] = 'base'
    resolver_class: ClassVar[type[BaseResolver]]
    termerrors: ClassVar[tuple[type[Exception], ...]] = (
        EOFError,
        KeyboardInterrupt,
        BrokenPipeError,
        UserQuit)

    class Options(BaseModel):
        qname: str
        rdtype: RdType = 'A'
        file: Path = Path(__file__).resolve().parent.parent/'config.example.yml'
        interval: RTime = 0.0
        count: NonNegativeInt = 0
        save: Path
        load: Path|None = False
        yaml: bool = False

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = ArgumentParser(description=cls.description)
        cls.add_arguments(parser)
        return parser

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        arg = parser.add_argument
        defaults = cls.Options(qname='', save=f'state.{cls.slug}.yml')
        arg('qname', help='Hostname to query')
        arg('rdtype', nargs='?', default=defaults.rdtype, help='Record type, default A')
        arg('--file', '-f', default=defaults.file, help='Path to yaml config file')
        arg('--interval', '-n', default=defaults.interval, help='Poll interval')
        arg('--count', '-c', default=defaults.count, help='Number of queries after which to quit')
        arg('--save', '-s', default=defaults.save, help='File to write state on save')
        arg('--load', '-l', help='State file to load')
        arg('--yaml', action='store_true', help='Print YAML')

    @classmethod
    def main(cls, args: Sequence[str]|None = None) -> None:
        parser = cls.create_parser()
        cls(parser, parser.parse_args(args)).run()

    def __init__(self, parser: ArgumentParser, opts: Any) -> None:
        self.parser = parser
        self.opts = self.Options.model_validate(opts, from_attributes=True)
        self.q = Question.model_validate(self.opts, from_attributes=True)
        self.keyaction = KeyAction(self)
        self.stdin = sys.stdin
        self.stdout = sys.stdout
        self.paused = False
        self.delay = 0.0
        self.count = 0

    def setup(self) -> None:
        self.tcorgattr = self.stdin.isatty() and termios.tcgetattr(self.stdin.fileno())
        with self.opts.file.open() as file:
            config = yaml.safe_load(file)
        self.resolver = self.resolver_class(config)
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
        try:
            rep = self.resolver.query(**self.q.model_dump(), delay=self.delay)
        except self.termerrors:
            raise
        except:
            logger.exception(f'Query failed')
        else:
            self.report(rep.model_dump() | self.resolver.state())
        self.count += 1
        if self.count >= self.opts.count > 0:
            raise UserQuit

    def readtty(self) -> None:
        start = time.monotonic()
        sargs = ([self.stdin.fileno()], [], [], 0)
        while True:
            if select(*sargs)[0]:
                key = self.stdin.read(1).upper()
                self.keyaction(key)
            t = time.monotonic() - start
            if not self.paused and 0 < self.opts.interval < t:
                raise UserContinue

    def save(self) -> None:
        with self.opts.save.open('w') as file:
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

    def __init__(self, cmd: BaseCommand) -> None:
        self.cmd = cmd

    def __call__(self, key: str) -> None:
        if key in self.keymap:
            getattr(self, f'cmd_{self.keymap[key]}')(self.cmd)

    def cmd_continue(self, cmd: BaseCommand) -> None:
        raise UserContinue

    def cmd_quit(self, cmd: BaseCommand) -> None:
        raise UserQuit

    def cmd_save(self, cmd: BaseCommand) -> None:
        cmd.save()
        cmd.report(save=cmd.opts.save.name)

    def cmd_pause(self, cmd: BaseCommand) -> None:
        if cmd.opts.interval:
            cmd.paused = not cmd.paused
            cmd.report(paused=cmd.paused)

    def cmd_delay(self, cmd: BaseCommand) -> None:
        opt = self.input('Delay for next query')
        try:
            cmd.delay = valrtime(opt or 0)
        except ValidationError as err:
            cmd.report(error=str(err))
            cmd.delay = 0.0
        cmd.report(delay=cmd.delay)

    def cmd_interval(self, cmd: BaseCommand) -> None:
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

    def cmd_anomaly(self, cmd: BaseCommand) -> None:
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
                cmd.report(anomaly=anomaly.model_dump(mode='json', exclude=['expiry']))
        else:
            anomaly = None
            cmd.report(anomaly=anomaly)
        cmd.resolver.anomaly = anomaly

    def cmd_faster(self, cmd: BaseCommand) -> None:
        if cmd.opts.interval:
            cmd.opts.interval = max(0.001, cmd.opts.interval / 1.5)
        else:
            cmd.opts.interval = 1.0
        cmd.report(interval=cmd.opts.interval)

    def cmd_slower(self, cmd: BaseCommand) -> None:
        cmd.opts.interval = min(300.0, cmd.opts.interval * 1.5)
        cmd.report(interval=cmd.opts.interval)

    def cmd_help(self, cmd: BaseCommand) -> None:
        cmd.report(help={
            key.replace('\n', '↵'): value
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

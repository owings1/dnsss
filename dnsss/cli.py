from __future__ import annotations

import enum
import json
import logging
import random
import re
import signal
import sys
import termios
import time
import tty
from argparse import ArgumentParser, Namespace
from collections import deque
from contextlib import contextmanager
from io import TextIOBase
from pathlib import Path
from select import select
from typing import (Annotated, Any, ClassVar, Generator, Iterable, Iterator,
                    Sequence)

import yaml

from . import settings
from .algs import ResolverType, registry
from .models import *

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
        cmd = cls(parser, parser.parse_args(args))
        cmd.setup()
        signal.signal(signal.SIGHUP, cmd.SIGHUP)
        cmd.run()

    def __init__(self, parser: ArgumentParser, nsopts: Namespace) -> None:
        self.stdout = sys.stdout
        self.stdin = sys.stdin
        self.parser = parser
        self.opts = self.options_model.model_validate(nsopts)

    def setup(self) -> None: ...

    def run(self) -> None: ...

    def SIGHUP(self, signum, frame) -> None: ...

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

class CommonOptions(CommandOptions):
    algorithm: Annotated[str, BeforeValidator(valalg)] = Field(
        default=settings.DEFAULT_ALG,
        validate_default=True)
    config: Path|None = None
    output: Path = Path('state.yml')
    load: Annotated[Path|bool, BeforeValidator(lambda x: x is None or x)] = Field(
        default=False,
        description='Load state from file')
    save: bool = False
    format: OutFormat = OutFormat[settings.DEFAULT_FORMAT]
    quiet: bool = False
    report: Path|None = None

    @property
    def table(self) -> bool:
        return self.format is self.format.table

class ClientOptions(CommonOptions):
    interval: NonNegativeFloat = 0.0
    count: NonNegativeInt = 0

class CommonCommand[O: CommonOptions](BaseCommand[O]):
    options_model: ClassVar = CommonOptions
    reloadable: ClassVar = ['output', 'save', 'report', 'format']

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        super().add_arguments(parser)
        arg = parser.add_argument
        arg(
            '--alg', '-a',
            type=str.lower,
            dest='algorithm',
            choices=list(registry),
            help='Resolver algorithm')
        arg(
            '--config', '-f',
            type=Path,
            help='Path to YAML config file')
        arg(
            '--output', '-o',
            help='File to write state on save')
        arg(
            '--save', '-s',
            action='store_true',
            help='Save state file automatically')
        arg(
            '--load', '-l',
            nargs='?',
            default=False,
            help='Load state from file')
        arg(
            '--format', '-F',
            choices=OutFormat,
            help=f'Output format, default {settings.DEFAULT_FORMAT}')
        arg('--quiet', '-q', action='store_true', help='Dont output report')
        arg('--report', '-r', help='Report to file instead of stdout')

    def __init__(self, parser: ArgumentParser, nsopts: Namespace) -> None:
        if nsopts.config:
            # Preload the config file before we construct the command options,
            # so we can specify default command options in the config file.
            logger.info(f'Reading config from {nsopts.config}')
            with open(nsopts.config) as file:
                self.config: dict = yaml.safe_load(file) or {}
            self.configcwd = nsopts.config.parent
        else:
            self.config = {}
            self.configcwd = Path('.')
        # Options set in the config file
        self.implicits = (
            self.options_model.model_validate(
                self.config.get('options') or {})
            .model_dump(exclude_unset=True))
        # Options passed on the command line take precedence
        UNSET = (None, False, ...)
        self.explicits = {
            name: value for name, value
            in vars(nsopts).items()
            if value not in UNSET}
        for name, value in self.implicits.items():
            if name in self.explicits:
                # Ignore config file for options set on the command line
                continue
            if isinstance(value, Path):
                # Relativize paths to config file if they were not
                # specified on the command line
                self.implicits[name] = value = self.configcwd/value
            if getattr(nsopts, name, ...) in UNSET:
                setattr(nsopts, name, value)
        for name in tuple(vars(nsopts)):
            # Clear empty values from args namespace
            if getattr(nsopts, name) in UNSET:
                delattr(nsopts, name)
        super().__init__(parser, nsopts)

    def setup(self) -> None:
        super().setup()
        self.resolver = registry[self.opts.algorithm](config=self.config)
        if self.opts.save and not self.opts.output.exists():
            # Initialize output file if save option is enabled, so if it is
            # the same as the --load file, we won't throw an error. Otherwise
            # you would have to call the program first without the --load argument,
            # then save the file, then change the command args the next time,
            # which is awkward.
            with self.opts.output.open('w') as file:
                yaml.safe_dump({}, file)
        if self.opts.load:
            if self.opts.load is True:
                self.opts.load = self.opts.output
            with self.opts.load.open() as file:
                state = yaml.safe_load(file) or {}
            self.resolver.state.load(state)

    def reload(self) -> None:
        "Reload the config file"
        if not self.opts.config:
            return
        with self.opts.config.open() as file:
            config: dict = yaml.safe_load(file) or {} 
        # Reload options
        implicits = (
            self.options_model.model_validate(
                config.get('options') or {})
            .model_dump(exclude_unset=True))
        names = (
            set(implicits).union(self.implicits)
            .intersection(self.reloadable)
            .difference(self.explicits))
        opts = self.opts
        for name in names:
            if name not in implicits:
                logger.info(f'Updating {name}')
                continue
            value = implicits[name]
            if isinstance(value, Path):
                implicits[name] = value = self.configcwd/value
            if getattr(opts, name) != value:
                logger.info(f'Updating {name}')
                setattr(opts, name, value)
        # Create new resolver
        resolver: ResolverType = type(self.resolver)(config=config)
        resolver.state.load(self.resolver.state)
        self.config, self.resolver, self.implicits, self.opts = (
            config, resolver, implicits, self.options_model.model_validate(opts))

    def save(self) -> None:
        "Save the resolver state to the file"
        data = self.resolver.state.model_dump()
        with self.opts.output.open('w') as file:
            yaml.safe_dump(data, file, sort_keys=False)

    def report(self, *args, **kw) -> None:
        if self.opts.report:
            with self.opts.report.open('w') as out:
                self.reportout(out, dict(*args, **kw), flush=False)
        elif not self.opts.quiet:
            self.reportout(self.stdout, dict(*args, **kw), flush=True)

    def reportusr(self, *args, **kw) -> None:
        self.reportout(self.stdout, dict(*args, **kw), flush=True)

    def reportout(self, out: TextIOBase, data: Any, flush: bool = False) -> None:
        if self.opts.format is OutFormat.json:
            json.dump(data, out, indent=2)
        else:
            yaml.dump(data, out, sort_keys=False, width=float('inf'))
        out.write('\n')
        if flush:
            if self.opts.format is not OutFormat.json:
                out.write('---\n')
                if not out.isatty():
                    # Piping to yq needs this
                    out.write('---\n---\n')
            out.flush()

    def SIGHUP(self, signum, frame) -> None:
        'SIGHUP handler'
        logger.warning(f'Received signal {signum} SIGHUP')
        logger.info(f'Reloading')
        try:
            self.reload()
        except:
            logger.exception(f'Reload failed')
        else:
            logger.info(f'Reload succeded')

class ClientCommand(CommonCommand[ClientOptions]):
    prog: ClassVar = 'dnsss'
    options_model: ClassVar = ClientOptions
    termerrors: ClassVar[tuple[type[Exception], ...]] = (
        EOFError,
        KeyboardInterrupt,
        BrokenPipeError,
        UserQuit)

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        super().add_arguments(parser)
        arg = parser.add_argument
        arg('--interval', '-n', help='Poll interval')
        arg('--count', '-c', help='Number of queries after which to quit')

    def setup(self) -> None:
        super().setup()
        self.paused = False
        self.count = 0
        self.anomaly: Anomaly|None = None
        self.keyaction = KeyAction(self)
        self.tcorgattr = (
            self.stdin.isatty() and
            termios.tcgetattr(self.stdin.fileno()))
        self.questions, self.anomalies = self.configextra()

    def reload(self) -> None:
        super().reload()
        self.questions, self.anomalies = self.configextra()

    def configextra(self) -> tuple[list[Question], deque[Anomaly]]:
        qentries = self.config.get('questions') or [settings.DEFAULT_QNAME]
        questions = list(resolve_questions(qentries, self.configcwd))
        anomalies = deque(
            map(Anomaly.model_validate, self.config.get('anomalies', [])))
        return questions, anomalies

    def run(self) -> None:
        with self.ttycontext():
            report = self.resolver.report(table=self.opts.table)
            self.report(report)
            if self.stdin.isatty():
                tty.setcbreak(self.stdin.fileno())
            try:
                while True:
                    self.loop()
            except self.termerrors:
                pass

    def loop(self) -> None:
        self.prep_anomaly()
        if self.stdin.isatty():
            try:
                self.readtty()
            except UserContinue:
                pass
        else:
            time.sleep(self.opts.interval or settings.INTERVAL_START)
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
            report |= self.resolver.report(table=self.opts.table)
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
        sargs = ([self.stdin.fileno()], [], [], settings.SELECT_TIMEOUT)
        while True:
            if select(*sargs)[0]:
                key = self.stdin.read(1).upper()
                self.keyaction(key)
            t = time.monotonic() - start
            if not self.paused and 0 < self.opts.interval < t:
                raise UserContinue

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
        'R': 'reload',
        'I': 'interval',
        'A': 'anomaly',
        '+': 'faster',
        '-': 'slower',
        '?': 'help'}

    def __init__(self, cmd: ClientCommand) -> None:
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
        cmd.reportusr(save=cmd.opts.output.name)

    def cmd_pause(self) -> None:
        cmd = self.cmd
        if cmd.opts.interval:
            cmd.paused = not cmd.paused
            cmd.reportusr(paused=cmd.paused)

    def cmd_reload(self) -> None:
        cmd = self.cmd
        cmd.reload()
        cmd.reportusr(reloaded=True)
        
    def cmd_interval(self) -> None:
        cmd = self.cmd
        opt = self.input('Set interval')
        try:
            interval = valnnf(opt or cmd.opts.interval)
        except ValidationError as err:
            cmd.reportusr(error=str(err))
        else:
            if interval:
                interval = min(
                    settings.INTERVAL_MAX,
                    max(settings.INTERVAL_MIN, interval))
            cmd.opts.interval = interval
            cmd.reportusr(interval=interval)

    def cmd_anomaly(self) -> None:
        cmd = self.cmd
        opt = self.input('Set anomaly: <pattern>/<delay>[/[limit]]')
        if opt:
            parts = opt.removesuffix('/').split('/')
            if len(parts) == 2:
                parts.append(None)
            try:
                pattern, delay, limit = parts
                anomaly = Anomaly(
                    limit=limit,
                    delayers=[dict(pattern=pattern, delay=delay)])
            except ValueError as err:
                cmd.reportusr(error=str(err))
                return
            else:
                cmd.reportusr(anomaly=anomaly.model_dump())
        else:
            anomaly = None
            cmd.reportusr(anomaly=anomaly)
        cmd.anomaly = anomaly
        cmd.prep_anomaly()

    def cmd_faster(self) -> None:
        cmd = self.cmd
        if cmd.opts.interval:
            cmd.opts.interval = max(
                settings.INTERVAL_MIN,
                cmd.opts.interval / settings.INTERVAL_STEP)
        else:
            cmd.opts.interval = settings.INTERVAL_START
        cmd.reportusr(interval=cmd.opts.interval)

    def cmd_slower(self) -> None:
        cmd = self.cmd
        cmd.opts.interval = min(
            settings.INTERVAL_MAX,
            cmd.opts.interval * settings.INTERVAL_STEP)
        cmd.reportusr(interval=cmd.opts.interval)

    def cmd_help(self) -> None:
        self.cmd.reportusr(help={
            key.replace('\n', '[enter]'): value
            for key, value in self.keymap.items()})

    def input(self, prompt: str|None = None) -> str:
        cmd = self.cmd
        if prompt:
            cmd.reportusr(prompt=prompt)
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

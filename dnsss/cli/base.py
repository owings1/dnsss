from __future__ import annotations

import argparse
import enum
import json
import logging
import os
import signal
import sys
from argparse import ArgumentParser, Namespace
from collections import deque
from io import TextIOBase
from pathlib import Path
from threading import RLock
from typing import Annotated, Any, ClassVar, Sequence

import yaml
from pydantic.fields import FieldInfo

from .. import settings
from ..algs import ResolverType, registry
from ..models import *
from ..utils import WatchedRotatingFileHandler

type SubParsers = argparse._SubParsersAction[ArgumentParser]

LogFormat = Annotated[
    str,
    BeforeValidator(lambda x: logging.PercentStyle(x).validate() or x)]

class OutFormat(enum.StrEnum):
    json = 'json'
    yaml = 'yaml'
    table = 'table'

class CommandOptions(BaseModel):
    model_config = ConfigDict(from_attributes=True)

class BaseCommand:
    prog: ClassVar[str|None] = None
    description: ClassVar[str|None] = None

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = ArgumentParser()
        cls.init_parser(parser)
        return parser

    @classmethod
    def init_parser(cls, parser: ArgumentParser) -> None:
        parser.description = cls.description or parser.description
        parser.prog = cls.prog or parser.prog

    @classmethod
    def main(cls, args: Sequence[str]|None = None) -> None:
        parser = cls.create_parser()
        cmd: ContainerCommand|ConcreteCommand = cls(parser, parser.parse_args(args))
        while isinstance(cmd, ContainerCommand):
            cmd = cmd.command
        cmd.setup()
        cmd.run()

class ContainerCommand(BaseCommand):
    commands: ClassVar[dict[str, type[BaseCommand]]] = {}
    command_metavar: ClassVar[str] = 'command'
    command_opt: ClassVar[str]
    command_name: str
    command: BaseCommand

    @classmethod
    def init_parser(cls, parser: ArgumentParser) -> None:
        super().init_parser(parser)
        cls.add_commands(parser)

    @classmethod
    def add_commands(cls, parser: ArgumentParser) -> None:
        "Setup subcommands for a container command defined in the `commands` dict"
        subparsers = cls.create_subparsers(parser)
        for name, cmd in cls.commands.items():
            subparser = subparsers.add_parser(name)
            cmd.init_parser(subparser)
            if not subparser.description:
                subparser.description = f'{name} command'

    @classmethod
    def create_subparsers(cls, parser: ArgumentParser) -> SubParsers:
        "Initialize the argument subparsers for a container command"
        return parser.add_subparsers(
            dest=cls.command_opt,
            metavar=cls.command_metavar,
            help=', '.join(cls.commands),
            required=True)

    def __init_subclass__(cls) -> None:
        cls.command_opt = f'_command_{abs(hash(cls))}'

    def __init__(self, parser: ArgumentParser, nsopts: Namespace) -> None:
        self.command_name = getattr(nsopts, self.command_opt)
        delattr(nsopts, self.command_opt)
        # Initialize the subcommand
        self.command = self.commands[self.command_name](parser, nsopts)

class ConcreteCommand[O: CommandOptions](BaseCommand):
    options_model: ClassVar[type[O]] = CommandOptions

    @classmethod
    def init_parser(cls, parser: ArgumentParser) -> None:
        super().init_parser(parser)
        cls.add_arguments(parser)
        cls.extend_actions(parser)

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        pass

    @classmethod
    def extend_actions(cls, parser: ArgumentParser) -> None:
        "Autofill parser actions from options fields"
        fields = cls.options_model.model_fields
        for action in parser._actions:
            if (field := fields.get(action.dest)):
                cls.extend_action(action, field)

    @classmethod
    def extend_action(cls, action: argparse.Action, field: FieldInfo) -> None:
        "Autofill an action from a DataModel field"
        if not action.help and (text := field.description or field.title):
            action.help = text

    def __init__(self, parser: ArgumentParser, nsopts: Namespace) -> None:
        self.stdout = sys.stdout
        self.stdin = sys.stdin
        self.parser = parser
        self.opts = self.options_model.model_validate(nsopts)

    def setup(self) -> None: ...

    def run(self) -> None: ...

def valalg(alg: str) -> str:
    alg = alg.lower()
    if alg in registry:
        return alg
    raise ValueError('Invalid algorithm')

class ClientServerBaseOptions(CommandOptions):
    "Common base class for client and server options"
    algorithm: Annotated[str, BeforeValidator(valalg)] = Field(
        default=settings.DEFAULT_ALGORITHM,
        validate_default=True,
        description=f'Resolver algorithm, default {settings.DEFAULT_ALGORITHM}')
    config: Path|None = Field(
        default=None,
        description='Path to YAML config file')
    output: Path = Field(
        default=Path('state.yml'),
        description='File to write state on save, default state.yml')
    load: Annotated[Path|bool, BeforeValidator(lambda x: x is None or x)] = Field(
        default=False,
        description='Load state from file')
    save: bool = Field(
        default=False,
        description='Save state file automatically')
    format: OutFormat = Field(
        default=OutFormat[settings.DEFAULT_FORMAT],
        description=f'Output format, default {settings.DEFAULT_FORMAT}')
    quiet: bool = Field(
        default=False,
        description='Dont output report')
    report: Path|None = Field(
        default=None,
        description='Report to file instead of stdout')
    replog: Path|None = Field(
        default=None,
        description='Query response log file')
    replog_format: LogFormat|None = Field(
        default=None,
        description=f'Custom response log format (%-style)')

    @property
    def table(self) -> bool:
        return self.format is self.format.table

class ClientServerBaseCommand[O: ClientServerBaseOptions](ConcreteCommand[O]):
    "Common base class for client and server commands"
    options_model: ClassVar = ClientServerBaseOptions
    logger: ClassVar = logging.getLogger('dnsss')
    reloadable: ClassVar = [
        'algorithm',
        'output',
        'save',
        'report',
        'format',
        'quiet',
        'replog_format']
    "Options fields that can be reloaded from the config file during runtime"
    fileable: ClassVar = ['load', 'replog']
    "Options fields that can be initialized from the config file, but not reloaded"

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        super().add_arguments(parser)
        arg = parser.add_argument
        arg(
            '--alg', '-a',
            type=str.lower,
            dest='algorithm',
            choices=list(registry))
        arg('--config', '-f', type=Path)
        arg('--output', '-o')
        arg('--save', '-s', action='store_true')
        arg('--load', '-l', nargs='?', default=False)
        arg('--format', '-F', choices=OutFormat)
        arg('--quiet', '-q', action='store_true')
        arg('--report', '-r')
        arg('--replog', '-L')
        arg('--replog-format', '-R')

    def __init__(self, parser: ArgumentParser, nsopts: Namespace) -> None:
        self._lock = RLock()
        self.replog = logging.getLogger(f'{self.logger.name}.response')
        if nsopts.config:
            # Preload the config file before we construct the command options,
            # so we can specify default command options in the config file.
            self.logger.info(f'Reading config from {nsopts.config}')
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
            .model_dump(include=self.reloadable + self.fileable))
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
        self.logger.info(f'PID: {os.getpid()}')
        self.anomaly: Anomaly|None = None
        self.anomalies = self.config_anomalies(self.config)
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
        if self.opts.replog:
            self.replog_handler = WatchedRotatingFileHandler(
                filename=self.opts.replog,
                delay=True,
                maxBytes=settings.REPLOG_MAXBYTES,
                backupCount=settings.REPLOG_KEEPCOUNT)
            self.set_replog_formatter()
            self.replog_handler.setLevel(logging.INFO)
            self.replog.addHandler(self.replog_handler)
        else:
            self.replog_handler = None
        self.prep_anomaly()
        signal.signal(signal.SIGHUP, self.SIGHUP)
        signal.signal(signal.SIGQUIT, self.SIGQUIT)

    def set_replog_formatter(self) -> None:
        if self.replog_handler:
            if self.opts.replog_format:
                formatter = logging.Formatter(self.opts.replog_format)
            else:
                formatter = self.replog.handlers[0].formatter
            self.replog_handler.setFormatter(formatter)

    def reload(self) -> None:
        "Reload the config file"
        with self._lock:
            from .. import backends
            backends.resolve_backend.cache_clear()
            if not self.opts.config:
                return
            with self.opts.config.open() as file:
                config: dict = yaml.safe_load(file) or {} 
            # Only consider options from tne config that are reloadable
            implicits = (
                self.options_model.model_validate(
                    config.get('options') or {})
                .model_dump(include=self.reloadable))
            # Only consider options from the config that were not explicitly
            # passed on the command line
            names = set(implicits).difference(self.explicits)
            # opts = self.opts
            opts = self.options_model(**self.opts.model_dump())
            for name in names:
                value = implicits[name]
                if isinstance(value, Path):
                    implicits[name] = value = self.configcwd/value
                if getattr(opts, name) != value:
                    self.logger.info(f'Updating option {name!r}')
                    setattr(opts, name, value)
            opts = self.options_model.model_validate(opts)
            anomalies = self.config_anomalies(config)
            # Create new resolver
            resolver: ResolverType = registry[self.opts.algorithm](config=config)
            resolver.state.load(self.resolver.state.model_dump())
            self.config, self.resolver, self.implicits, self.opts, self.anomalies = (
                config, resolver, implicits, opts, anomalies)
            self.prep_anomaly()
            self.set_replog_formatter()

    def save(self) -> None:
        "Save the resolver state to the file"
        with self._lock:
            data = self.resolver.state.model_dump()
            with self.opts.output.open('w') as file:
                yaml.safe_dump(data, file, sort_keys=False)

    def report(self, *args, **kw) -> None:
        if self.opts.report:
            with self._lock:    
                with self.opts.report.open('w') as out:
                    self.reportout(out, dict(*args, **kw), flush=False)
        elif not self.opts.quiet:
            self.reportout(self.stdout, dict(*args, **kw), flush=True)

    def reportusr(self, *args, **kw) -> None:
        self.reportout(self.stdout, dict(*args, **kw), flush=True)

    def reportout(self, out: TextIOBase, data: Any, flush: bool = False) -> None:
        with self._lock:
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

    def config_anomalies(self, config: dict) -> deque[Anomaly]:
        return deque(
            map(Anomaly.model_validate, config.get('anomalies', [])))

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

    def SIGHUP(self, signum, frame) -> None:
        'SIGHUP handler'
        self.logger.warning(f'Received signal {signum} SIGHUP')
        self.logger.info(f'Reloading')
        try:
            self.reload()
        except:
            self.logger.exception(f'Reload failed')
        else:
            self.logger.info(f'Reload succeded')

    def SIGQUIT(self, signum, frame) -> None:
        'SIGQUIT handler'
        self.logger.warning(f'Received signal {signum} SIGQUIT')
        self.quit = True

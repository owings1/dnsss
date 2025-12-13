from __future__ import annotations

import json
import logging
import random
import re
import termios
import time
import tty
from argparse import ArgumentParser
from contextlib import contextmanager
from pathlib import Path
from select import select
from threading import Thread
from typing import Any, ClassVar, Generator, Iterable, Iterator

from .. import settings
from ..models import *
from .base import ClientServerBaseCommand, ClientServerBaseOptions


class UserQuit(Exception):
    pass

class UserContinue(Exception):
    pass

class UserHupping(Exception):
    pass

class ClientOptions(ClientServerBaseOptions):
    interval: NonNegativeFloat = Field(
        default=0.0,
        description='Poll interval')
    count: NonNegativeInt = Field(
        default=0,
        description='Number of queries after which to quit')
    sequential: bool = Field(
        default=False,
        description=(
            'Iterate once over questions in sequence order, then quit. '
            'If count is non-zero, it is treated as max'))
    threads: PositiveInt = Field(
        default=1,
        description='Number of threads to use')

class ClientCommand(ClientServerBaseCommand[ClientOptions]):
    logger: ClassVar = logging.getLogger(f'dnsss.client')
    options_model: ClassVar = ClientOptions
    reloadable: ClassVar = ClientServerBaseCommand.reloadable + ['interval', 'count', 'sequential']
    fileable: ClassVar = ClientServerBaseCommand.fileable + ['threads']
    termerrors: ClassVar[tuple[type[Exception], ...]] = (
        EOFError,
        KeyboardInterrupt,
        BrokenPipeError,
        UserQuit)

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        super().add_arguments(parser)
        arg = parser.add_argument
        arg('--interval', '-n')
        arg('--count', '-c')
        arg('--sequential', '-S', action='store_true')
        arg('--threads', '-t')

    def setup(self) -> None:
        super().setup()
        self.hupping = False
        self.quit = False
        self.paused = False
        self.count = 0
        self.keyaction = KeyAction(self)
        self.tcorgattr = (
            self.stdin.isatty() and
            termios.tcgetattr(self.stdin.fileno()))
        self.questions = self.config_questions(self.config)
        self.logger.info(f'Loaded {len(self.questions)} questions')

    def reload(self) -> None:
        with self._lock:
            super().reload()
            self.questions = self.config_questions(self.config)

    def run(self) -> None:
        with self.ttycontext():
            report = self.resolver.report(table=self.opts.table)
            self.report(report)
            if self.stdin.isatty():
                tty.setcbreak(self.stdin.fileno())
            errors = []
            def target():
                try:
                    while not (self.quit or errors):
                        try:
                            self.loop()
                        except UserHupping:
                            # Yield lock to SIGHUP and restart loop
                            time.sleep(settings.HUPPING_DELAY)
                            continue
                except self.termerrors:
                    self.quit = True
                except Exception as err:
                    self.quit = True
                    errors.append(err)
                    self.logger.exception(f'Unexpected error')
            threads = [Thread(target=target) for _ in range(self.opts.threads)]
            for thread in threads:
                thread.start()
            try:
                for thread in threads:
                    thread.join()
            except self.termerrors:
                pass
            if errors:
                raise errors[-1]

    def loop(self) -> None:
        with self._lock:
            self.prep_anomaly()
            if self.stdin.isatty():
                try:
                    self.readtty()
                except UserContinue:
                    pass
            else:
                time.sleep(self.opts.interval or settings.INTERVAL_START)
            if self.count >= self.opts.count > 0:
                raise UserQuit
            if self.opts.sequential:
                try:
                    q = self.questions[self.count]
                except IndexError:
                    raise UserQuit from None
            else:
                q = random.choice(self.questions)
            self.count += 1
        try:
            rep = self.resolver.query(q)
        except self.termerrors:
            raise
        except:
            self.logger.exception(f'Query failed')
        else:
            extra = rep.report()|rep.q.report()|dict(
                rrjson=json.dumps(rep.rrset),
                arjson=json.dumps(rep.arset),
                aujson=json.dumps(rep.auset))
            report = dict(query=rep.report())
            with self._lock:
                self.replog.info('%(code)s', dict(code=rep.code), extra=extra)
                if self.anomaly:
                    if self.anomaly.limit is not None:
                        self.anomaly.limit -= 1
                    report.update(anomaly=self.anomaly.report())
                report |= self.resolver.report(table=self.opts.table)
                self.report(report)
        finally:
            if self.opts.save:
                self.save()
        if self.count >= self.opts.count > 0:
            raise UserQuit
        if self.opts.sequential and self.count >= len(self.questions):
            raise UserQuit

    def readtty(self) -> None:
        start = time.monotonic()
        sargs = ([self.stdin.fileno()], [], [], settings.SELECT_TIMEOUT)
        while True:
            if select(*sargs)[0]:
                key = self.stdin.read(1).upper()
                self.keyaction(key)
            t = time.monotonic() - start
            if (
                self.hupping and 
                (self.paused or not self.opts.interval) and
                t > settings.HUPPING_RELEASE / self.opts.threads):
                # Avoid deadlock on SIGHUP when idle
                raise UserHupping
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

    def config_questions(self, config: dict) -> list[Question]:
        qentries = config.get('questions') or [settings.DEFAULT_QNAME]
        return list(resolve_questions(qentries, self.configcwd))

    def SIGHUP(self, signum, frame) -> None:
        if self.hupping:
            self.logger.warning(f'Ignoring extra SIGHUP, already in progress')
            return
        self.hupping = True
        try:
            super().SIGHUP(signum, frame)
        finally:
            self.hupping = False

class KeyAction:
    keymap: ClassVar[dict[str, str]] = {
        '\n': 'continue',
        'Q': 'quit',
        'S': 'save',
        'P': 'pause',
        'R': 'reload',
        'I': 'interval',
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
            interval = float(opt or cmd.opts.interval)
        except ValueError as err:
            cmd.reportusr(error=str(err))
        else:
            if interval:
                interval = min(
                    settings.INTERVAL_MAX,
                    max(settings.INTERVAL_MIN, interval))
            cmd.opts.interval = interval
            cmd.reportusr(interval=interval)

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
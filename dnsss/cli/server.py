from __future__ import annotations

import logging
import signal
import time
from argparse import ArgumentParser
from pathlib import Path
from typing import ClassVar

from .. import settings
from ..models import *
from ..utils import WatchedRotatingFileHandler
from .base import CommonCommand, CommonOptions, LogFormat

replog = logging.getLogger(f'dnsss.server.response')

class ServerOptions(CommonOptions):
    address: IPvAnyAddress = Field(
        default=IPvAnyAddress(settings.LISTEN_ADDRESS),
        description=f'Bind address, default {settings.LISTEN_ADDRESS}')
    port: Port = Field(
        default=settings.LISTEN_PORT,
        description=f'Listen port, default {settings.LISTEN_PORT}')
    replog: Path|None = Field(
        default=None,
        description='Query response log file')
    replog_format: LogFormat|None = Field(
        default=None,
        description=f'Custom response log format (%-style)')

class ServerCommand(CommonCommand[ServerOptions]):
    options_model: ClassVar = ServerOptions
    logger: ClassVar = logging.getLogger(f'dnsss.server')
    reloadable: ClassVar = CommonCommand.reloadable + ['replog_format']
    fileable: ClassVar = CommonCommand.fileable + ['address', 'port', 'replog']

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        super().add_arguments(parser)
        arg = parser.add_argument
        arg('--port', '-p')
        arg('--address', '-b')
        arg('--replog')
        arg('--replog-format')

    def setup(self) -> None:
        super().setup()
        self.quit = False
        if self.opts.replog:
            self.replog_handler = WatchedRotatingFileHandler(
                filename=self.opts.replog,
                delay=True,
                maxBytes=settings.REPLOG_MAXBYTES,
                backupCount=settings.REPLOG_KEEPCOUNT)
            self.set_replog_formatter()
            self.replog_handler.setLevel(logging.INFO)
            replog.addHandler(self.replog_handler)
        else:
            self.replog_handler = None
        from ..server import DualServer
        self.server = DualServer(
            address=self.opts.address,
            port=self.opts.port,
            resolver=self.resolver,
            reports=True,
            table=self.opts.table)
        signal.signal(signal.SIGQUIT, self.SIGQUIT)

    def set_replog_formatter(self) -> None:
        if self.replog_handler:
            if self.opts.replog_format:
                self.replog_handler.setFormatter(logging.Formatter(self.opts.replog_format))
            else:
                self.replog_handler.setFormatter(replog.handlers[0].formatter)
            
    def reload(self) -> None:
        super().reload()
        self.set_replog_formatter()
        # Update reference after reload
        self.server.resolver = self.resolver
        self.server.table = self.opts.table

    def run(self) -> None:
        self.server.start()
        try:
            while not self.quit:
                self.loop()
        except KeyboardInterrupt:
            pass
        finally:
            self.server.shutdown()

    def loop(self) -> None:
        reports = self.server.reports
        if reports:
            # Only print the latest
            report = reports.pop()
            if self.anomaly:
                if self.anomaly.limit is not None:
                    self.anomaly.limit -= 1 + len(reports)
                report.update(anomaly=self.anomaly.report())
            self.report(report)
            reports.clear()
            if self.opts.save:
                self.save()
            self.prep_anomaly()
        time.sleep(settings.SERVER_SLEEP_DELAY)

    def SIGQUIT(self, signum, frame) -> None:
        'SIGQUIT handler'
        self.logger.warning(f'Received signal {signum} SIGQUIT')
        self.quit = True

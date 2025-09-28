from __future__ import annotations

import logging
import signal
import time
from argparse import ArgumentParser
from pathlib import Path
from typing import ClassVar

from .. import settings
from ..models import *
from .base import CommonCommand, CommonOptions


class ServerOptions(CommonOptions):
    address: IPvAnyAddress = Field(
        default=IPvAnyAddress(settings.LISTEN_ADDRESS),
        description='Bind address')
    port: Port = Field(
        default=settings.LISTEN_PORT,
        description='Listen port')
    replog: Path|None = Field(
        default=None,
        description='Query response log file')

class ServerCommand(CommonCommand[ServerOptions]):
    options_model: ClassVar = ServerOptions
    logger: ClassVar = logging.getLogger(f'dnsss.server')
    fileable: ClassVar = CommonCommand.fileable + ['address', 'port', 'replog']

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        super().add_arguments(parser)
        arg = parser.add_argument
        arg('--port', '-p')
        arg('--address', '-b')
        arg('--replog')

    def setup(self) -> None:
        super().setup()
        from .. import server
        self.quit = False
        if self.opts.replog:
            from logging.handlers import RotatingFileHandler
            handler = RotatingFileHandler(
                filename=self.opts.replog,
                delay=True,
                maxBytes=settings.REPLOG_MAXBYTES,
                backupCount=settings.REPLOG_KEEPCOUNT)
            handler.formatter = server.replog.handlers[0].formatter
            handler.setLevel(logging.INFO)
            server.replog.addHandler(handler)
        self.server = server.DualServer(
            address=self.opts.address,
            port=self.opts.port,
            resolver=self.resolver,
            reports=True,
            table=self.opts.table)
        signal.signal(signal.SIGQUIT, self.SIGQUIT)

    def reload(self) -> None:
        super().reload()
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

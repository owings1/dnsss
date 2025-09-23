from __future__ import annotations

import logging
import signal
import socket
import time
from argparse import ArgumentParser
from collections import deque
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

    @property
    def address_family(self) -> socket.AddressFamily:
        if self.address.version == 6:
            return socket.AddressFamily.AF_INET6
        return socket.AddressFamily.AF_INET

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
        self.reports: deque[dict] = deque()
        # Make resolver a property for the Handler class, since the reference
        # changes on reload() when a new instance is created
        def resolver(_):
            return self.resolver
        # Likewise for table option
        def table(_):
            return self.opts.table
        ns = dict(
            resolver=property(resolver),
            reports=self.reports,
            table=property(table))
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
        self.server = server.DualServer(self.opts, ns)
        signal.signal(signal.SIGQUIT, self.SIGQUIT)

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
        if self.reports:
            # Only print the latest
            report = self.reports.pop()
            if self.anomaly:
                if self.anomaly.limit is not None:
                    self.anomaly.limit -= 1 + len(self.reports)
                report.update(anomaly=self.anomaly.report())
            self.report(report)
            self.reports.clear()
            if self.opts.save:
                self.save()
            self.prep_anomaly()
        time.sleep(settings.SERVER_SLEEP_DELAY)

    def SIGQUIT(self, signum, frame) -> None:
        'SIGQUIT handler'
        self.logger.warning(f'Received signal {signum} SIGQUIT')
        self.quit = True

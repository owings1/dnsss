from __future__ import annotations

import logging
import time
from argparse import ArgumentParser
from typing import ClassVar

from .. import settings
from ..models import *
from .base import ClientServerBaseCommand, ClientServerBaseOptions


class ServerOptions(ClientServerBaseOptions):
    address: IPvAnyAddress = Field(
        default=IPvAnyAddress(settings.LISTEN_ADDRESS),
        description=f'Bind address, default {settings.LISTEN_ADDRESS}')
    port: Port = Field(
        default=settings.LISTEN_PORT,
        description=f'Listen port, default {settings.LISTEN_PORT}')

class ServerCommand(ClientServerBaseCommand[ServerOptions]):
    options_model: ClassVar = ServerOptions
    logger: ClassVar = logging.getLogger(f'dnsss.server')
    fileable: ClassVar = ClientServerBaseCommand.fileable + ['address', 'port']

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        super().add_arguments(parser)
        arg = parser.add_argument
        arg('--port', '-p')
        arg('--address', '-b')

    def setup(self) -> None:
        super().setup()
        self.quit = False
        from ..server import DualServer
        self.server = DualServer(
            address=self.opts.address,
            port=self.opts.port,
            resolver=self.resolver,
            reports=True,
            table=self.opts.table)
            
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

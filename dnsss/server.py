from __future__ import annotations

import logging
import socket
import socketserver
import struct
import time
from abc import abstractmethod
from argparse import ArgumentParser
from collections import deque
from threading import Thread
from typing import Callable, ClassVar, Self

from dnslib import (CLASS, QTYPE, RCODE, RDMAP, RR, DNSHeader, DNSLabel, HTTPS,
                    DNSRecord)

from .algs.base import Resolver
from .cli import CommonCommand, CommonOptions
from .models import *

SLEEP_DELAY = 0.1
TCP_BUF_SIZE = 8192 * 1
logger = logging.getLogger(__name__)

class BaseHandler(socketserver.BaseRequestHandler):
    resolver: Resolver
    onquery: Callable[[Self, Response], None]

    def handle(self) -> None:
        try:
            request = DNSRecord.parse(self.read())
            reply = self.resolve(request)
            self.send(reply.pack())
        except Exception as err:
            logger.exception(f'{err!r}')

    def resolve(self, request: DNSRecord) -> DNSRecord:
        header = DNSHeader(id=request.header.id, qr=1, aa=1, ra=1)
        reply = DNSRecord(header=header, q=request.q)
        response = None
        try:
            response = self.resolver.query(dict(
                qname=str(request.q.qname),
                rdtype=QTYPE[request.q.qtype]))
            self.onquery(self, response)
            if response.code == 'NOERROR':
                reply.add_answer(*map(self.buildrr, response.rset))
            else:
                reply.header.rcode = getattr(RCODE, response.code, RCODE.SERVFAIL)
        except:
            logger.exception(f'{request=} {response=}')
            reply.header.rcode = RCODE.SERVFAIL
        return reply

    @staticmethod
    def buildrr(rstr: str) -> RR:
        rname, ttl, rclass, rtype, rdata = rstr.split(maxsplit=4)
        if rtype == 'HTTPS':
            rdata = HTTPS.fromZone(rdata.split())
        else:
            rdata = RDMAP[rtype](rdata)
        return RR(
            rname=DNSLabel(rname),
            ttl=int(ttl),
            rclass=getattr(CLASS, rclass),
            rtype=getattr(QTYPE, rtype),
            rdata=rdata)

    @abstractmethod
    def read(self) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def send(self, data: bytes) -> None:
        raise NotImplementedError

class UDPHandler(BaseHandler):
    request: tuple[bytes, socket.socket]

    def read(self) -> bytes:
        return self.request[0]

    def send(self, data: bytes) -> None:
        self.request[1].sendto(data, self.client_address)

class TCPHandler(BaseHandler):
    """
    Adapted from:
    
    Simple DNS server (UDP and TCP) in Python using dnslib.py

    Philipp Klaus <philipp.l.klaus@web.de>
        https://github.com/pklaus
        https://gist.github.com/pklaus/b5a7876d4d2cf7271873

    Andrei Fokau
        https://andrei.fokau.se/
        https://github.com/andreif
        https://gist.github.com/andreif/6069838

    Apache 2.0 License
    http://www.apache.org/licenses/LICENSE-2.0
    """
    request: socket.socket

    def read(self) -> bytes:
        data = self.request.recv(TCP_BUF_SIZE).strip()
        sz: int = struct.unpack('>H', data[:2])[0]
        if sz != len(data) - 2:
            raise ValueError(f'Wrong size of TCP packet {sz=} ln={len(data)}')
        return data[2:]

    def send(self, data: bytes) -> None:
        sz = struct.pack('>H', len(data))
        self.request.sendall(sz + data)

class ServerMixin: 
    BaseHandler: type[BaseHandler]

    def __init__(self, opts: ServeOptions, ns: dict, **kw) -> None:
        self.address_family = opts.address_family
        Handler = type(self.BaseHandler.__name__, (self.BaseHandler,), ns)
        super().__init__((str(opts.address), opts.port), Handler, **kw)

class TCPServer(ServerMixin, socketserver.ThreadingTCPServer):
    BaseHandler = TCPHandler

class UDPServer(ServerMixin, socketserver.ThreadingUDPServer):
    BaseHandler = UDPHandler

class ServeOptions(CommonOptions):
    address: IPvAnyAddress = IPvAnyAddress('127.0.0.1')
    port: PositiveInt = 5053

    @property
    def address_family(self) -> socket.AddressFamily:
        if self.address.version == 6:
            return socket.AddressFamily.AF_INET6
        return socket.AddressFamily.AF_INET

class ServeCommand(CommonCommand[ServeOptions]):
    options_model: ClassVar = ServeOptions

    @classmethod
    def add_arguments(cls, parser: ArgumentParser) -> None:
        super().add_arguments(parser)
        defaults = cls.options_model()
        parser.add_argument('--port', '-p', default=defaults.port)
        parser.add_argument('--address', '-b', default=defaults.address)

    def setup(self) -> None:
        super().setup()
        self.reports = deque()
        ns = dict(resolver=self.resolver, onquery=self.onquery)
        self.servers = (UDPServer(self.opts, ns), TCPServer(self.opts, ns))

    def run(self) -> None:
        threads = [
            Thread(
                target=server.serve_forever,
                name=type(server).__name__,
                daemon=True)
            for server in self.servers]
        listenaddr = f'{self.opts.address}:{self.opts.port}'
        for thread in threads:
            logger.info(f'Starting {thread.name} listening on {listenaddr}')
            thread.start()
        try:
            self.loop()
        except KeyboardInterrupt:
            pass
        finally:
            for thread, server in zip(threads, self.servers):
                logger.info(f'Stopping {thread.name}')
                server.shutdown()

    def loop(self) -> None:
        report = None
        while True:
            try:
                report = self.reports.popleft()
            except IndexError:
                if report:
                    if self.opts.save:
                        self.save()
                        report = None
                time.sleep(SLEEP_DELAY)
            else:
                self.report(report)

    def onquery(self, handler: BaseHandler, rep: Response) -> None:
        table = self.opts.format == 'table' and self.opts.tablefmt
        self.reports.append(dict(
            peer=handler.client_address[0],
            query=rep.report(),
            state=self.resolver.state.report(table=table)))

if __name__ == '__main__':
    logger = logging.getLogger(f'{__package__}.server')
    logging.basicConfig(level=logging.INFO)
    ServeCommand.main()

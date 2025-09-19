from __future__ import annotations

import json
import logging
import os
import socket
import socketserver
import struct
import time
from abc import abstractmethod
from argparse import ArgumentParser
from collections import deque
from pathlib import Path
from threading import Thread
from typing import Callable, ClassVar, Literal, Self

from dnslib import (CLASS, HTTPS, QTYPE, RCODE, RDMAP, RR, DNSHeader, DNSLabel,
                    DNSRecord)

from . import settings
from .algs import ResolverType
from .cli import CommonCommand, CommonOptions
from .models import *

logger = logging.getLogger(f'dnsss.server')
replog = logging.getLogger(f'dnsss.server.response')

class BaseHandler(socketserver.BaseRequestHandler):
    proto: Literal['TCP', 'UDP']
    resolver: ResolverType
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
    proto = 'UDP'
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
    proto = 'TCP'
    request: socket.socket

    def read(self) -> bytes:
        data = self.request.recv(settings.TCP_BUF_SIZE).strip()
        sz: int = struct.unpack('>H', data[:2])[0]
        if sz != len(data) - 2:
            raise ValueError(f'Wrong size TCP packet {sz=} ln={len(data) - 2}')
        return data[2:]

    def send(self, data: bytes) -> None:
        self.request.sendall(struct.pack('>H', len(data)) + data)

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
    address: IPvAnyAddress = IPvAnyAddress(settings.LISTEN_ADDRESS)
    port: Port = settings.LISTEN_PORT
    replog: Path|None = None

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
        arg = parser.add_argument
        arg('--port', '-p')
        arg('--address', '-b')
        arg('--replog')

    def setup(self) -> None:
        super().setup()
        self.reports = deque()
        # Make resolver a property for the Handler class, since the reference
        # changes on reload() when a new instance is created
        def resolver(_):
            return self.resolver
        ns = dict(resolver=property(resolver), onquery=self.onquery)
        self.servers = (UDPServer(self.opts, ns), TCPServer(self.opts, ns))
        if self.opts.replog:
            hdler: logging.FileHandler = replog.handlers[0]
            hdler.baseFilename = str(self.opts.replog)
            hdler.setLevel(logging.INFO)

    def run(self) -> None:
        logger.info(f'PID: {os.getpid()}')
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
            while True:
                self.loop()
        except KeyboardInterrupt:
            pass
        finally:
            for thread, server in zip(threads, self.servers):
                logger.info(f'Stopping {thread.name}')
                server.shutdown()

    def loop(self) -> None:
        if self.reports:
            # Only print the latest
            self.report(self.reports.pop())
            self.reports.clear()
            if self.opts.save:
                self.save()
        time.sleep(settings.SERVER_SLEEP_DELAY)

    def onquery(self, handler: BaseHandler, rep: Response) -> None:
        data = dict(
            peer=handler.client_address[0],
            proto=handler.proto,
            query=rep.report())
        rjson = json.dumps(rep.rset)
        extra = data|data['query']|dict(tag=rep.tag, rjson=rjson)
        replog.info('%(code)s', dict(code=rep.code), extra=extra)
        data |= self.resolver.report(table=self.opts.table)
        self.reports.append(dict(data))

if __name__ == '__main__':
    ServeCommand.main()

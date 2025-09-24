from __future__ import annotations

import json
import logging
import os
import socket
import socketserver
import struct
from abc import abstractmethod
from collections import deque
from threading import Thread
from typing import TYPE_CHECKING, Literal

from dnslib import QTYPE, RR, DNSHeader, DNSRecord

from .algs import ResolverType
from .models import *

if TYPE_CHECKING:
    from .cli.server import ServerOptions

logger = logging.getLogger(f'dnsss.server')
replog = logging.getLogger(f'dnsss.server.response')

class BaseHandler(socketserver.BaseRequestHandler):
    proto: Literal['TCP', 'UDP']
    resolver: ResolverType
    reports: deque = deque(maxlen=0)
    table: bool = True

    def setup(self) -> None:
        self.response = None

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
        try:
            q = Question(
                qname=str(request.q.qname),
                rdtype=QTYPE[request.q.qtype])
            self.response = rep = self.resolver.query(q)
            code = rep.code
            if code is code.NOERROR:
                if q.rdtype is RdType.SVCB:
                    code = code.NOTIMP
                else:
                    for rr in rep.rset:
                        reply.add_answer(*RR.fromZone(rr))
        except:
            logger.exception(f'{request=} response={self.response}')
            code = Rcode.SERVFAIL
        reply.header.rcode = int(code)
        return reply

    def finish(self) -> None:
        if not (rep := self.response):
            return
        try:
            data = dict(
                peer=self.client_address[0],
                proto=self.proto,
                query=rep.report())
            rjson = json.dumps(rep.rset)
            extra = data|data['query']|dict(tag=rep.tag, rjson=rjson)
            replog.info('%(code)s', dict(code=rep.code), extra=extra)
            data |= self.resolver.report(table=self.table)
            self.reports.append(dict(data))
        except Exception as err:
            logger.exception(f'{err!r}')

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

class TCPHandler(socketserver.StreamRequestHandler, BaseHandler):
    proto = 'TCP'
    request: socket.socket

    def read(self) -> bytes:
        data = self.rfile.read(2)
        if len(data) != 2:
            # struct.error: unpack requires a buffer of 2 bytes
            raise NoisyPacket
        size: int = struct.unpack('>H', data)[0]
        data = self.rfile.read(size)
        if len(data) != size:
            raise BadPacket(f'{size=} length={len(data)}')
        return data

    def send(self, data: bytes) -> None:
        self.wfile.write(struct.pack('>H', len(data)))
        self.wfile.write(data)

    def finish(self) -> None:
        super().finish()
        BaseHandler.finish(self)

class ServerMixin: 
    BaseHandler: type[BaseHandler]

    def __init__(self, opts: ServerOptions, ns: dict, **kw) -> None:
        self.address_family = opts.address_family
        Handler = type(self.BaseHandler.__name__, (self.BaseHandler,), ns)
        super().__init__((str(opts.address), opts.port), Handler, **kw)

class TCPServer(ServerMixin, socketserver.ThreadingTCPServer):
    BaseHandler = TCPHandler

class UDPServer(ServerMixin, socketserver.ThreadingUDPServer):
    BaseHandler = UDPHandler

class DualServer:

    def __init__(self, opts: ServerOptions, ns: dict) -> None:
        self.opts = opts
        self.servers = (
            UDPServer(self.opts, ns),
            TCPServer(self.opts, ns))

    def start(self) -> None:
        logger.info(f'PID: {os.getpid()}')
        self.threads = [
            Thread(
                target=server.serve_forever,
                name=type(server).__name__,
                daemon=True)
            for server in self.servers]
        listenaddr = f'{self.opts.address}:{self.opts.port}'
        for thread in self.threads:
            logger.info(f'Starting {thread.name} listening on {listenaddr}')
            thread.start()

    def shutdown(self) -> None:
        for thread, server in zip(self.threads, self.servers):
            logger.info(f'Stopping {thread.name}')
            server.shutdown()

class NoisyPacket(ValueError):
    pass

class BadPacket(ValueError):
    pass

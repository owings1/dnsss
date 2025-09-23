from __future__ import annotations

import json
import logging
import os
import socket
import socketserver
import struct
from abc import abstractmethod
from threading import Thread
from collections import deque
from typing import TYPE_CHECKING, Literal

from dnslib import (CLASS, HTTPS, QTYPE, RCODE, RDMAP, RR, DNSHeader, DNSLabel,
                    DNSRecord)

from . import settings
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
    table: bool|str = True

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
            self.response = rep = self.resolver.query(dict(
                qname=str(request.q.qname),
                rdtype=QTYPE[request.q.qtype]))
            if rep.code == 'NOERROR':
                reply.add_answer(*filter(None, map(self.buildrr, rep.rset)))
            else:
                reply.header.rcode = getattr(RCODE, rep.code, RCODE.SERVFAIL)
        except:
            logger.exception(f'{request=} response={self.response}')
            reply.header.rcode = RCODE.SERVFAIL
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

    @staticmethod
    def buildrr(rstr: str) -> RR|None:
        rname, ttl, rclass, rtype, rdata = rstr.split(maxsplit=4)
        if rtype == 'HTTPS':
            rdata = HTTPS.fromZone(rdata.split())
        elif rtype == 'SVCB':
            logger.warning(f'{rtype} Not Implemented ({rstr=})')
            return
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

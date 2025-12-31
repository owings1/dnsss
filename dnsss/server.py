from __future__ import annotations

import json
import logging
import socket
import socketserver
import struct
from abc import abstractmethod
from collections import deque
from threading import Thread

from dns.flags import Flag
from dnslib import (CLASS, EDNS0, QTYPE, RR, SRV, DNSBuffer, DNSHeader,
                    DNSRecord)

from . import settings
from .algs import ResolverType
from .models import *

__all__ = ['DualServer']

type BaseServerType = socketserver.BaseServer|ServerMixin

logger = logging.getLogger(f'dnsss.server')
replog = logging.getLogger(f'dnsss.server.response')

class DualServer:

    def __init__(self, address: IPvAnyAddress, port: Port, resolver: ResolverType, reports: bool = False, table: bool = True, srvsort: bool = False) -> None:
        self.address = address
        self.port = port
        self.resolver = resolver
        self.reports: deque[dict] = deque(maxlen=None if reports else 0)
        self.table = table
        self.srvsort = srvsort

    def start(self) -> None:
        logger.info(f'Listen: {self.address}:{self.port}')
        self.servers = (UDPServer(self), TCPServer(self))
        self.threads = [
            Thread(
                target=server.serve_forever,
                name=type(server).__name__,
                daemon=True)
            for server in self.servers]
        for thread in self.threads:
            logger.info(f'Starting {thread.name}')
            thread.start()

    def shutdown(self) -> None:
        for thread, server in zip(self.threads, self.servers):
            logger.info(f'Stopping {thread.name}')
            server.shutdown()

    def report(self, handler: BaseHandler) -> None:
        if not (rep := handler.response):
            return
        data = dict(
            peer=handler.client_address[0],
            proto=handler.proto,
            query=rep.report())
        extra = data|dict(ername='')|data['query']|rep.q.report()|dict(
            id=handler.reply.header.id,
            tag=rep.tag,
            rrjson=json.dumps(rep.rrset),
            arjson=json.dumps(rep.arset),
            aujson=json.dumps(rep.auset))
        replog.info('%(code)s', dict(code=rep.code), extra=extra)
        data |= self.resolver.report(table=self.table)
        self.reports.append(dict(data))

class BaseHandler(socketserver.BaseRequestHandler):
    proto: Proto
    maxlen: PositiveInt
    'Max message length'
    server: BaseServerType
    edns0: EDNS0|None = settings.EDNS_BUFSIZE and EDNS0(udp_len=settings.EDNS_BUFSIZE) or None

    def setup(self) -> None:
        self.response: Response|None = None
        self.resolver: ResolverType = self.server.server.resolver
        self.srvsort: bool = self.server.server.srvsort
        # This buffer is just to track the message size, and is not actually sent.
        self.rbuf = DNSBuffer()

    def handle(self) -> None:
        try:
            try:
                request = DNSRecord.parse(self.read())
            except BadPacket as err:
                self.send(b'')
                if isinstance(err, NoisyPacket):
                    func = logger.debug
                else:
                    func = logger.warning
                func(f'Bad Packet from {self.client_address[0]}: {err!r}')
            else:
                reply = self.resolve(request)
                self.send(reply.pack())
        except Exception as err:
            logger.exception(f'{err!r} {self.client_address=}')

    def resolve(self, request: DNSRecord) -> DNSRecord:
        header = DNSHeader(id=request.header.id, qr=1, rd=request.header.rd)
        self.reply = reply = DNSRecord(header=header, q=request.q)
        header.pack(self.rbuf)
        request.q.pack(self.rbuf)
        if self.edns0:
            reply.add_ar(self.edns0)
            self.edns0.pack(self.rbuf)
        try:
            q = Question(
                qname=str(request.q.qname),
                rdtype=QTYPE[request.q.qtype],
                rdclass=CLASS[request.q.qclass],
                flags=0x100 * bool(header.rd))
            self.response = rep = self.resolver.query(q)
            rep.id = header.id
            code = rep.code
            flag = Flag(rep.flags)
            header.ra = Flag.RA in flag
            header.ad = Flag.AD in flag
            header.cd = Flag.CD in flag
            header.aa = Flag.AA in flag
            header.tc = Flag.TC in flag
            if code is code.NOERROR:
                if q.rdtype is RdType.SVCB:
                    code = code.NOTIMP
                else:
                    self.addanswers()
            elif code is code.NXDOMAIN:
                self.addanswers()
        except:
            logger.exception(f'{request=} response={self.response}')
            code = Rcode.SERVFAIL
        reply.header.rcode = int(code)
        return reply

    def addanswers(self) -> None:
        """
        Add the staged records to the reply. When the reply buffer has reached
        the max size, set the truncate flag (tc), and stop adding answers.
        """
        rep = self.response
        maxlen = self.maxlen - len(rep.q.qname)
        reply = self.reply
        rrset = [RR.fromZone(rstr)[0] for rstr in rep.rrset]
        arset = [RR.fromZone(rstr)[0] for rstr in rep.arset]
        auset = [RR.fromZone(rstr)[0] for rstr in rep.auset]
        if rep.q.rdtype is RdType.SRV and self.srvsort and rrset:
            # Sort SRV records by values
            rrset.sort(key=srvsortkey)
        rsetfuncs = (
            # The answer rrset
            (rrset, reply.add_answer),
            # The additional records section
            (arset, reply.add_ar),
            # The authority section
            (auset, reply.add_auth))
        buf = self.rbuf
        for rset, add in rsetfuncs:
            for rr in rset:
                rr.pack(buf)
                if len(buf.data) > maxlen:
                    logger.debug(f'Truncating size={len(buf.data)}')
                    reply.header.tc = True
                    return
                add(rr)

    def finish(self) -> None:
        try:
            self.server.server.report(self)
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
    # Reference: https://www.netmeister.org/blog/dns-size.html
    maxlen: PositiveInt = settings.UDP_MAXLEN
    request: tuple[bytes, socket.socket]

    def read(self) -> bytes:
        return self.request[0]

    def send(self, data: bytes) -> None:
        self.request[1].sendto(data, self.client_address)

class TCPHandler(socketserver.StreamRequestHandler, BaseHandler):
    proto = 'TCP'
    maxlen: PositiveInt = 65530
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

    def setup(self) -> None:
        super().setup()
        BaseHandler.setup(self)

    def finish(self) -> None:
        super().finish()
        BaseHandler.finish(self)

class ServerMixin: 
    BaseHandler: type[BaseHandler]
    server: DualServer

    def __init__(self, server: DualServer, **kw) -> None:
        self.server = server
        if server.address.version == 6:
            self.address_family = socket.AddressFamily.AF_INET6
        else:
            self.address_family = socket.AddressFamily.AF_INET
        super().__init__(
            (str(server.address), server.port),
            type(self.BaseHandler.__name__, (self.BaseHandler,), {}),
            **kw)

class TCPServer(ServerMixin, socketserver.ThreadingTCPServer):
    BaseHandler = TCPHandler

class UDPServer(ServerMixin, socketserver.ThreadingUDPServer):
    BaseHandler = UDPHandler

class BadPacket(ValueError):
    pass

class NoisyPacket(BadPacket):
    pass

def srvsortkey(rr: RR) -> tuple[int, int, int, str]:
    """Sort SRV records by priority, weight, port, target hostname."""
    rdata: SRV = rr.rdata
    return (rdata.priority, rdata.weight, rdata.port, rdata.target.idna())
    
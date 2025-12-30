from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from .models import *

type ResolveFuncRet = BackendResponse|dict[str, Any]
type ResolveFunc = Callable[[Question, NonNegativeFloat, bool, IPvAnyAddress|None], ResolveFuncRet]

logger = logging.getLogger(__name__)

@functools.cache
def resolve_backend(server: Server) -> ResolveFunc:
    'Create the backend resolve function for the server'
    try:
        if server.lower() == 'refuse':
            return refuse
        if server.startswith('file@'):
            return file_backend(server.removeprefix('file@'))
        if server.startswith('mock'):
            configstr, = (server.split('@', maxsplit=1)[1:] or [''])
            opts = dict(
                itemstr.split('=') for itemstr in
                filter(None, configstr.split(',')))
            return mock_backend(**opts)
        return dnspython_backend(*server.split('@', maxsplit=1))
    except:
        logger.exception(f'Failed to create backend for {server!r}')
        raise

def dnspython_backend(where: str, port: int|str = 53) -> ResolveFunc:
    "Make a backend resolve function for a server/port using dnspython"
    import dns.resolver
    from dns.message import Message, QueryMessage
    backend = dns.resolver.make_resolver_at(
        where=where,
        port=int(port),
        resolver=dns.resolver.Resolver(configure=False))
    def resolve(q: Question, lifetime: NonNegativeFloat, tcp: bool, source: IPvAnyAddress|None) -> ResolveFuncRet:
        rrset = []
        arset = []
        auset = []
        extra = {}
        try:
            rep = backend.resolve(
                **q.model_dump(),
                raise_on_no_answer=False,
                lifetime=lifetime,
                tcp=tcp,
                source=source and str(source))
        except dns.resolver.NoMetaqueries:
            code = Rcode.REFUSED
        except dns.resolver.YXDOMAIN:
            code = Rcode.YXDOMAIN
        except dns.resolver.NXDOMAIN as nx:
            code = Rcode.NXDOMAIN
            msg: Message
            for msg in nx.responses().values():
                if msg.id:
                    extra.update(id=msg.id)
                arset.extend(rstrs(msg.additional))
                auset.extend(rstrs(msg.authority))
        except dns.resolver.NoNameservers as no:
            code = Rcode.SERVFAIL
            qm: QueryMessage = no.kwargs['request']
            extra.update(id=qm.id, ername=ErName.NoNameservers)
        except dns.resolver.LifetimeTimeout:
            code = Rcode.SERVFAIL
            extra.update(ername=ErName.Timeout)
        else:
            extra.update(id=rep.response.id, flags=rep.response.flags)
            code = Rcode(rep.response.rcode().name)
            rrset.extend(map(str, rep.chaining_result.cnames))
            rrset.extend(rstrs(rep.rrset))
            arset.extend(rstrs(rep.response.additional))
            auset.extend(rstrs(rep.response.authority))
        return BackendResponse(
            **extra,
            code=code,
            rrset=rrset,
            arset=arset,
            auset=auset)
    return resolve

def mock_backend(**opts) -> ResolveFunc:
    "Make a mock backend resolve function"
    mock = MockServer.model_validate(opts)
    import ipaddress
    import random
    import re
    from itertools import islice
    net4 = ipaddress.ip_network('10.0.0.0/8')
    net6 = ipaddress.ip_network('fe80::/64')
    # <n>.size.example will return n-many A or AAAA records
    sizepat = re.compile(r'^(\d+)\.size\.example\.$')
    def resolve(q: Question, lifetime: NonNegativeFloat, tcp: bool, source: IPvAnyAddress|None) -> ResolveFuncRet:
        d = random.uniform(0, mock.v)
        rtime = mock.r * (1 + d)
        rrset = []
        extra = {}
        if rtime >= lifetime:
            code = Rcode.SERVFAIL
            rtime = lifetime
            extra.update(ername=ErName.Timeout)
        else:
            code = Rcode.NOERROR
            if q.rdclass is q.rdclass.IN:
                if q.rdtype is q.rdtype.A:
                    it = net4.hosts()
                elif q.rdtype is q.rdtype.AAAA:
                    it = net6.hosts()
                else:
                    it = iter(())
                if (m := sizepat.match(q.qname)):
                    count = int(m[1])
                else:
                    count = 1
                for rd in islice(it, count):
                    rrset.append(f'{q.qname} 0 {q.rdclass} {q.rdtype} {rd}')
        return BackendResponse(
            **extra,
            code=code,
            rrset=rrset,
            rtime=rtime)
    return resolve

def file_backend(file: str) -> ResolveFunc:
    """
    Make a static YAML map file backend function.
    
    Example format::
    
        # zone.yml
        demo.domain.example. IN A:
            rrset: [demo.domain.example. 300 IN A 10.2.3.4]
            arset: [demo.domain.example. 300 IN AAAA ffff::1]
            auset: [demo.domain.example. 0 IN SOA demo.domain.example. root.demo.domain.example. 1 7200 900 1209600 86400]
    """
    import logging
    import yaml
    with open(file) as fp:
        data = yaml.safe_load(fp)
    logger = logging.getLogger(__name__)
    def resolve(q: Question, lifetime: NonNegativeFloat, tcp: bool, source: IPvAnyAddress|None) -> ResolveFuncRet:
        try:
            return data[f'{q.qname.lower()} {q.rdclass} {q.rdtype}']
        except KeyError:
            return {}
        except:
            logger.exception(f'{q=}')
            return dict(code=Rcode.SERVFAIL)
    return resolve

def refuse(q: Question, lifetime: NonNegativeFloat, tcp: bool, source: IPvAnyAddress|None) -> ResolveFuncRet:
    return dict(code=Rcode.REFUSED)

def unescape(s: str) -> str:
    return s.replace(r'\@', '@')

def rstrs(rset: Any) -> Rset:
    if not rset:
        return []
    if isinstance(rset, list):
        rset = '\n'.join(map(str, rset))
    return unescape(str(rset)).splitlines()
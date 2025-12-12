from __future__ import annotations

import functools
from typing import Any, Callable

from .models import *

type ResolveFuncRet = BackendResponse|dict[str, Any]
type ResolveFunc = Callable[[Question, NonNegativeFloat, bool], ResolveFuncRet]

@functools.cache
def resolve_backend(server: Server) -> ResolveFunc:
    'Create the backend resolve function for the server'
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

def dnspython_backend(where: str, port: int|str = 53) -> ResolveFunc:
    "Make a backend resolve function for a server/port using dnspython"
    import dns.resolver
    backend = dns.resolver.make_resolver_at(where, int(port))
    def unescape(s: str) -> str:
        return s.replace(r'\@', '@')
    def resolve(q: Question, lifetime: NonNegativeFloat, tcp: bool) -> ResolveFuncRet:
        rrset = []
        arset = []
        auset = []
        extra = {}
        try:
            rep = backend.resolve(
                **q.model_dump(),
                raise_on_no_answer=False,
                lifetime=lifetime,
                tcp=tcp)
        except dns.resolver.NoMetaqueries:
            code = Rcode.REFUSED
        except dns.resolver.NXDOMAIN:
            code = Rcode.NXDOMAIN
        except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            code = Rcode.SERVFAIL
        else:
            extra.update(id=rep.response.id)
            code = Rcode(rep.response.rcode().name)
            rrset.extend(map(str, rep.chaining_result.cnames))
            if rep.rrset:
                rrset.extend(unescape(str(rep.rrset)).splitlines())
            if rep.response.additional:
                for rset in rep.response.additional:
                    arset.extend(unescape(str(rset)).splitlines())
            if rep.response.authority:
                for rset in rep.response.authority:
                    auset.extend(unescape(str(rset)).splitlines())
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
    def resolve(q: Question, lifetime: NonNegativeFloat, tcp: bool) -> ResolveFuncRet:
        d = random.uniform(0, mock.v)
        rtime = mock.r * (1 + d)
        rrset = []
        if rtime >= lifetime:
            code = Rcode.SERVFAIL
            rtime = lifetime
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
    def resolve(q: Question, lifetime: NonNegativeFloat, tcp: bool) -> ResolveFuncRet:
        try:
            return data[f'{q.qname.lower()} {q.rdclass} {q.rdtype}']
        except KeyError:
            return {}
        except:
            logger.exception(f'{q=}')
            return dict(code=Rcode.SERVFAIL)
    return resolve

def refuse(q: Question, lifetime: NonNegativeFloat, tcp: bool) -> ResolveFuncRet:
    return dict(code=Rcode.REFUSED)
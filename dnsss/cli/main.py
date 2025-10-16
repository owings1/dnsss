from __future__ import annotations

from .base import ContainerCommand
from .client import ClientCommand
from .server import ServerCommand


class MainCommand(ContainerCommand):
    prog = 'dnsss'
    commands = dict(
        client=ClientCommand,
        server=ServerCommand)

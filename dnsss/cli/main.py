from __future__ import annotations

from .base import BaseCommand
from .client import ClientCommand
from .server import ServerCommand


class MainCommand(BaseCommand):
    prog = 'dnsss'
    commands = dict(
        client=ClientCommand,
        server=ServerCommand)

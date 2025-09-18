from __future__ import annotations

from os import getenv

DEFAULT_ALG = getenv('DEFAULT_ALG', 'bind')
DEFAULT_FORMAT = getenv('DEFAULT_FORMAT', 'table')
DEFAULT_QNAME = getenv('DEFAULT_QNAME', 'google.com')
DEFAULT_TABLEFMT = getenv('DEFAULT_TABLEFMT', 'simple')
INTERVAL_MAX = max(0.0, float(getenv('INTERVAL_MAX', 300.0)))
INTERVAL_MIN = max(0.0, float(getenv('INTERVAL_MIN', 0.001)))
INTERVAL_STEP = max(0.0, float(getenv('INTERVAL_STEP', 1.5)))
INTERVAL_START = max(0.0, float(getenv('INTERVAL_START', 1.0)))
LISTEN_ADDRESS = getenv('LISTEN_ADDRESS', '127.0.0.1')
LISTEN_PORT = int(getenv('LISTEN_PORT', 5053))
SELECT_TIMEOUT = max(0.0, float(getenv('SELECT_TIMEOUT', 0.01)))
SERVER_SLEEP_DELAY = max(0.0, float(getenv('SERVER_SLEEP_DELAY', 0.1)))
TCP_BUF_SIZE = max(1, int(getenv('SERVER_SLEEP_DELAY', 8192)))
YAML_FLOAT_PRECISION = max(1, int(getenv('YAML_FLOAT_PRECISION', 6)))
YAML_FLOAT_FMT = f'.{YAML_FLOAT_PRECISION}f'

# Populated in __init__
LOGGING_CONFIG = {}

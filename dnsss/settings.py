from __future__ import annotations

from os import getenv

DEFAULT_ALGORITHM = getenv('DEFAULT_ALG', 'AR1')
DEFAULT_FORMAT = getenv('DEFAULT_FORMAT', 'table')
DEFAULT_QNAME = getenv('DEFAULT_QNAME', 'google.com')
INTERVAL_MAX = max(0.0, float(getenv('INTERVAL_MAX', 300.0)))
INTERVAL_MIN = max(0.0, float(getenv('INTERVAL_MIN', 0.001)))
INTERVAL_STEP = max(0.0, float(getenv('INTERVAL_STEP', 1.5)))
INTERVAL_START = max(0.0, float(getenv('INTERVAL_START', 1.0)))
HUPPING_RELEASE = max(0.5, float(getenv('HUPPING_RELEASE', 1.0)))
HUPPING_DELAY = max(0.01, float(getenv('HUPPING_DELAY', 0.01)))
LISTEN_ADDRESS = getenv('LISTEN_ADDRESS', '127.0.0.1')
LISTEN_PORT = int(getenv('LISTEN_PORT', 5053))
SELECT_TIMEOUT = max(0.0, float(getenv('SELECT_TIMEOUT', 0.01)))
SERVER_SLEEP_DELAY = max(0.0, float(getenv('SERVER_SLEEP_DELAY', 0.1)))
REPLOG_MAXBYTES = max(0, int(getenv('REPLOG_MAXBYTES', 0)))
REPLOG_KEEPCOUNT = max(0, int(getenv('REPLOG_KEEPCOUNT', 0)))
UDP_MAXLEN = max(503, int(getenv('UDP_MAXLEN', 9192)))
YAML_FLOAT_PRECISION = max(1, int(getenv('YAML_FLOAT_PRECISION', 6)))
YAML_FLOAT_FMT = f'.{YAML_FLOAT_PRECISION}f'

# Populated in __init__
LOGGING_CONFIG = {}

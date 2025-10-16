import logging.config
from pathlib import Path

import dotenv
import yaml

dotenv.load_dotenv()

from . import settings

def _initlogging():
    file = Path(__file__).parent.resolve()/'logging.yml'
    with file.open() as fp:
        config = yaml.safe_load(fp)
    settings.LOGGING_CONFIG.update(config)
    logging.config.dictConfig(settings.LOGGING_CONFIG)

_initlogging()
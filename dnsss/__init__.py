import dotenv
import yaml
import logging.config
from pathlib import Path

dotenv.load_dotenv()

def _initlogging():
    file = Path(__file__).parent.resolve()/'logging.yml'
    with file.open() as fp:
        config = yaml.safe_load(fp)
    logging.config.dictConfig(config)

_initlogging()
"""
app/extensions.py
Initializes shared Flask extensions separately from the application factory
to prevent circular imports across routes and middleware.
"""

import logging
import sys
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


limiter = Limiter(key_func=get_remote_address)


def configure_logger() -> logging.Logger:
    """
    Configures a structured stream logger writing to stdout for container/PaaS compatibility.
    """
    logger = logging.getLogger("phishing_api")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


logger = configure_logger()
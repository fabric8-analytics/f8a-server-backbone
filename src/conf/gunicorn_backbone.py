"""Gunicorn config."""

import logging
from src.settings import GUNICORN_SETTINGS

workers = GUNICORN_SETTINGS.workers
worker_class = GUNICORN_SETTINGS.worker_class
timeout = GUNICORN_SETTINGS.timeout
preload_app = GUNICORN_SETTINGS.preload
reload = preload_app != True


def when_ready(server):  # noqa
    """Log when worker is ready to serve."""
    logger = logging.getLogger(__name__)
    logger.info(
        "Starting backbone gunicorn with %s workers %s worker class and preload %s",
        workers,
        worker_class,
        preload_app,
    )

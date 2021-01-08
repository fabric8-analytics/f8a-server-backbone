import logging
from src.settings import GUNICORN_SETTINGS

workers = GUNICORN_SETTINGS.workers
worker_class = GUNICORN_SETTINGS.worker_class
timeout = GUNICORN_SETTINGS.timeout

preload_app = True
reload = True


def when_ready(server):
    logger = logging.getLogger(__name__)
    logger.debug(
        "Starting backbone gunicorn with %s workers and %s worker class", workers, worker_class
    )

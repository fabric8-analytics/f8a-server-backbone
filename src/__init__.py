"""The source code for f8a-server-backbone."""
import os
import logging


# Set root logger format for uniform log format.
log_level = os.environ.get('FLASK_LOGGING_LEVEL', logging.getLevelName(logging.WARNING))
logging.basicConfig(level=log_level,
                    format='[%(asctime)s] %(levelname)s in %(module)s:%(lineno)d: %(message)s')

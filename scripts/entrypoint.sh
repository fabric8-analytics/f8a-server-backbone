#!/usr/bin/bash

# Start API backbone service with time out
gunicorn -b 0.0.0.0:$API_BACKBONE_SERVICE_PORT -c src/conf/gunicorn_backbone.py src.rest_api:app --log-level $FLASK_LOGGING_LEVEL

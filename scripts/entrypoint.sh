#!/usr/bin/bash

# Start API backbone service with time out
gunicorn --pythonpath /src/ -b 0.0.0.0:$API_BACKBONE_SERVICE_PORT -t $API_BACKBONE_SERVICE_TIMEOUT -k $CLASS_TYPE -w $NUMBER_WORKER_PROCESS rest_api:app --reload --preload --max-requests 32 --max-requests-jitter 32 --log-level $FLASK_LOGGING_LEVEL

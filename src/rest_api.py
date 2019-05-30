"""Implementation of the REST API for the backbone service."""

import os
import flask
import logging
from f8a_worker.setup_celery import init_selinon
from flask import Flask, request, current_app
from flask_cors import CORS
from recommender import RecommendationTask
from stack_aggregator import StackAggregator
from raven.contrib.flask import Sentry
from requests_futures.sessions import FuturesSession
from datetime import datetime
from src.utils import select_from_db

worker_count = int(os.getenv('FUTURES_SESSION_WORKER_COUNT', '100'))
_session = FuturesSession(max_workers=worker_count)
stack_analysis_workers = ["stack_aggregator_v2", "recommendation_v2"]

METRICS_COLLECTION_URL = "{base_url}:{port}/api/v1/prometheus".format(
    base_url = os.environ.get("METRICS_ENDPOINT_URL"),
    port= os.environ.get("METRICS_ENDPOINT_URL_PORT"))

format = "%Y-%m-%dT%H:%M:%S.%f"

def setup_logging(flask_app):
    """Perform the setup of logging (file, log level) for this application."""
    if not flask_app.debug:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'))
        log_level = os.environ.get('FLASK_LOGGING_LEVEL', logging.getLevelName(logging.WARNING))
        handler.setLevel(log_level)

        flask_app.logger.addHandler(handler)
        flask_app.config['LOGGER_HANDLER_POLICY'] = 'never'
        flask_app.logger.setLevel(logging.DEBUG)


app = Flask(__name__)
setup_logging(app)
CORS(app)
SENTRY_DSN = os.environ.get("SENTRY_DSN", "")
sentry = Sentry(app, dsn=SENTRY_DSN, logging=True, level=logging.ERROR)

init_selinon()


@app.route('/api/v1/readiness')
def readiness():
    """Handle GET requests that are sent to /api/v1/readiness REST API endpoint."""
    return flask.jsonify({}), 200


@app.route('/api/v1/liveness')
def liveness():
    """Handle GET requests that are sent to /api/v1/liveness REST API endpoint."""
    return flask.jsonify({}), 200


@app.route('/api/v1/recommender', methods=['POST'])
def recommender():
    """Handle POST requests that are sent to /api/v1/recommender REST API endpoint."""
    r = {'recommendation': 'failure', 'external_request_id': None}
    status = 400
    input_json = request.get_json()
    current_app.logger.debug('recommender/ request with payload: {p}'.format(p=input_json))

    if input_json and 'external_request_id' in input_json and input_json['external_request_id']:
        try:
            check_license = request.args.get('check_license', 'false') == 'true'
            persist = request.args.get('persist', 'true') == 'true'
            r = RecommendationTask().execute(input_json, persist=persist,
                                             check_license=check_license)
            status = 200
        except Exception as e:
            r = {
                'recommendation': 'unexpected error',
                'external_request_id': input_json.get('external_request_id'),
                'message': '%s' % e
            }
            status = 500
    push_data(data=r, pid=os.getpid(), hostname=os.environ.get("HOSTNAME"), endpoint=request.endpoint, method=request.method)
    return flask.jsonify(r), status


@app.route('/api/v1/stack_aggregator', methods=['POST'])
def stack_aggregator():
    """Handle POST requests that are sent to /api/v1/stack_aggregator REST API endpoint."""
    s = {'stack_aggregator': 'failure', 'external_request_id': None}
    input_json = request.get_json()
    current_app.logger.debug('stack_aggregator/ request with payload: {p}'.format(p=input_json))
    payload = {
        "pid": os.getpid(),
        "hostname" : os.environ.get("HOSTNAME"),
        "endpoint" : request.endpoint,
        "method" : request.method
    }
    if input_json and 'external_request_id' in input_json and input_json['external_request_id']:
        try:
            persist = request.args.get('persist', 'true') == 'true'
            s = StackAggregator().execute(input_json, persist=persist)
            status_code = 200
            total_time_elapsed(sa_audit_data=s['result']['_audit'],
                               external_request_id=input_json['external_request_id'],
                               worker=stack_analysis_workers[1])

        except Exception as e:
            s = {
                'stack_aggregator': 'unexpected error',
                'external_request_id': input_json.get('external_request_id'),
                'message': '%s' % e
            }
            status_code = 400

        push_data(data=s, status_code=status_code, **payload)
    return flask.jsonify(s)


def total_time_elapsed(sa_audit_data, external_request_id, worker):
    """
     Pushes Combined Metrics data to specified Url. Called in Stack Aggregator Only
    :param: sa_audit_data: Stack Aggregator Audit Data
    :param: external_request_id: Stack Id
    :param: worker: recommender_v2
    :return: Metrics Data
    """
    input_json = request.get_json()
    current_app.logger.debug('total_time_elapsed/ request with payload: {p}'.format(p=input_json))
    payload = {
        "pid": os.getpid(),
        "hostname": os.environ.get("HOSTNAME"),
        "endpoint": request.endpoint,
        "request_method": request.method,
    }

    re_db_data = select_from_db(external_request_id=input_json["external_request_id"], worker=worker)

    if (re_db_data is None) and (sa_audit_data is None):
        current_app.logger.debug('No Data found wrt Stack Id : {p}'.format(p=external_request_id))
        payload["value"] = 0
        payload["status_code"] = 400
        return _session.post(url=METRICS_COLLECTION_URL, json=payload)

    sa_started_at = sa_audit_data.get('started_at', re_db_data.started_at)
    sa_ended_at = sa_audit_data.get('ended_at', re_db_data.ended_at)

    if isinstance(sa_started_at, str):
        sa_started_at = datetime.strptime(sa_started_at, format)

    if isinstance(sa_ended_at, str):
        sa_ended_at = datetime.strptime(sa_ended_at, format)

    re_started_at = getattr(re_db_data, 'started_at', sa_started_at)
    re_ended_at = getattr(re_db_data, 'ended_at',  sa_ended_at)
    analysis_started_at = sa_started_at if sa_started_at < re_started_at else re_started_at
    analysis_ended_at = sa_ended_at if re_ended_at < sa_ended_at else re_ended_at
    timedelta = (analysis_ended_at - analysis_started_at).total_seconds()
    payload["value"] = timedelta
    payload["status_code"] = 200
    return _session.post(url=METRICS_COLLECTION_URL, json=payload)


def push_data(data, pid, hostname, endpoint, method, status_code):
    """
    This will Push individual Payload data (SA or RE Data) to specified url
    :param data: Audit Data
    :param pid: Process Id
    :param hostname: Hostname
    :param endpoint: Function Name
    :param method: POST/GET
    :return: Metrics Data
    """
    audit = data['result']['_audit']
    timedelta = (datetime.strptime(audit['ended_at'], format) - datetime.strptime(audit['started_at'], format)).total_seconds()
    payload = {
        "value": timedelta,
        "pid": pid,
        "hostname": hostname,
        "endpoint": endpoint,
        "request_method": method,
        "status_code": status_code
    }
    return _session.post(url=METRICS_COLLECTION_URL, json=payload)

if __name__ == "__main__":
    app.run()

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
from src.utils import push_data, total_time_elapsed, get_time_delta


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
    metrics_payload = {
        'pid': os.getpid(),
        'hostname': os.environ.get("HOSTNAME"),
        'endpoint': request.endpoint,
        'request_method': request.method,
        'status_code': 200
    }

    input_json = request.get_json()
    current_app.logger.debug('recommender/ request with payload: {p}'.format(p=input_json))

    if input_json and 'external_request_id' in input_json and input_json['external_request_id']:
        try:
            check_license = request.args.get('check_license', 'false') == 'true'
            persist = request.args.get('persist', 'true') == 'true'
            r = RecommendationTask().execute(input_json, persist=persist,
                                             check_license=check_license)
        except Exception as e:
            r = {
                'recommendation': 'unexpected error',
                'external_request_id': input_json.get('external_request_id'),
                'message': '%s' % e
            }
            metrics_payload['status_code'] = 400

    try:
        metrics_payload['value'] = get_time_delta(audit_data=r['result']['_audit'])
        push_data(metrics_payload)
    except KeyError:
        pass

    return flask.jsonify(r), metrics_payload['status_code']


@app.route('/api/v1/stack_aggregator', methods=['POST'])
def stack_aggregator():
    """Handle POST requests that are sent to /api/v1/stack_aggregator REST API endpoint."""
    s = {'stack_aggregator': 'failure', 'external_request_id': None}
    input_json = request.get_json()
    metrics_payload = {
        'pid': os.getpid(),
        'hostname': os.environ.get("HOSTNAME"),
        'endpoint': 'api_v1.get_stack_analyses',
        'request_method': request.method,
        'status_code': 200
    }

    if input_json and 'external_request_id' in input_json \
            and input_json['external_request_id']:

        try:
            persist = request.args.get('persist', 'true') == 'true'
            s = StackAggregator().execute(input_json, persist=persist)
            if s is not None and s.get('result') and s.get('result').get('_audit'):
                # Creating and Pushing Total Metrics Data to Accumulator
                metrics_payload['value'] = total_time_elapsed(
                    sa_audit_data=s['result']['_audit'],
                    external_request_id=input_json['external_request_id'])
                push_data(metrics_payload)

        except Exception as e:
            s = {
                'stack_aggregator': 'unexpected error',
                'external_request_id': input_json.get('external_request_id'),
                'message': '%s' % e
            }
            metrics_payload['status_code'] = 400

        try:
            # Pushing Individual Metrics Data to Accumulator
            metrics_payload['value'] = get_time_delta(audit_data=s['result']['_audit'])
            metrics_payload['endpoint'] = request.endpoint
            push_data(metrics_payload)
        except KeyError:
            pass

    return flask.jsonify(s)


if __name__ == "__main__":
    app.run()

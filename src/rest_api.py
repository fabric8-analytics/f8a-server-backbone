"""Implementation of the REST API for the backbone service."""

import flask
import logging
import os
import time

from f8a_worker.setup_celery import init_selinon
from flask import Flask, request
from flask_cors import CORS
from raven.contrib.flask import Sentry

from src.utils import push_data, total_time_elapsed
from src.v2.recommender import RecommendationTask as RecommendationTaskV2
from src.v2.stack_aggregator import StackAggregator as StackAggregatorV2

logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
SENTRY_DSN = os.environ.get("SENTRY_DSN", "")
sentry = Sentry(app, dsn=SENTRY_DSN, logging=True, level=logging.ERROR)

init_selinon()


@app.route('/api/readiness')
def readiness():
    """Handle GET requests that are sent to /api/readiness REST API endpoint."""
    return flask.jsonify({}), 200


@app.route('/api/liveness')
def liveness():
    """Handle GET requests that are sent to /api/liveness REST API endpoint."""
    return flask.jsonify({}), 200


def _recommender(handler):
    external_request_id = 'None'
    recommender_started_at = time.time()

    input_json = request.get_json()
    external_request_id = input_json['external_request_id']
    logger.info('%s recommender/ request', external_request_id)
    check_license = request.args.get('check_license', 'false') == 'true'
    persist = request.args.get('persist', 'true') == 'true'
    r = handler.execute(input_json, persist=persist,
                        check_license=check_license)
    logger.info('%s took %0.2f seconds for _recommender',
                external_request_id, time.time() - recommender_started_at)

    return flask.jsonify(r)


def _stack_aggregator(handler):
    external_request_id = 'None'
    stack_aggregator_started_at = time.time()

    assert handler
    s = {'stack_aggregator': 'failure', 'external_request_id': None}
    input_json = request.get_json()
    # (fixme) Create decorator for metrics handling.
    metrics_payload = {
        'pid': os.getpid(),
        'hostname': os.environ.get("HOSTNAME"),
        'endpoint': request.endpoint,
        'request_method': request.method,
        'status_code': 200
    }

    external_request_id = input_json['external_request_id']
    logger.info('%s stack_aggregator/ request', external_request_id)

    try:
        persist = request.args.get('persist', 'true') == 'true'
        s = handler.execute(input_json, persist=persist)
        if s.get('result', {}).get('_audit'):
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
        # Pushing Individual Metrics Data to Accumulator
        metrics_payload['value'] = 0
        push_data(metrics_payload)
        logger.error('%s failed %s', external_request_id, s)
        raise e

    logger.info('%s took %0.2f seconds for _stack_aggregators',
                external_request_id, time.time() - stack_aggregator_started_at)

    return flask.jsonify(s)


@app.route('/api/v2/recommender', methods=['POST'])
def recommender_v2():
    """Handle POST requests that are sent to /api/v2/recommender REST API endpoint."""
    return _recommender(RecommendationTaskV2())


@app.route('/api/v2/stack_aggregator', methods=['POST'])
def stack_aggregator_v2():
    """Handle POST requests that are sent to /api/v2/stack_aggregator REST API endpoint."""
    return _stack_aggregator(StackAggregatorV2())


if __name__ == "__main__":
    app.run()

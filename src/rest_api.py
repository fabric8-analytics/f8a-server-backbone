"""Implementation of the REST API for the backbone service."""

import os
import flask
import logging
from f8a_worker.setup_celery import init_selinon
from flask import Flask, request, current_app
from flask_cors import CORS
from recommender import RecommendationTask
from stack_aggregator import StackAggregator


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

    return flask.jsonify(r), status


@app.route('/api/v1/stack_aggregator', methods=['POST'])
def stack_aggregator():
    """Handle POST requests that are sent to /api/v1/stack_aggregator REST API endpoint."""
    s = {'stack_aggregator': 'failure', 'external_request_id': None}
    input_json = request.get_json()
    current_app.logger.debug('stack_aggregator/ request with payload: {p}'.format(p=input_json))
    if input_json and 'external_request_id' in input_json and input_json['external_request_id']:
        try:
            persist = request.args.get('persist', 'true') == 'true'
            s = StackAggregator().execute(input_json, persist=persist)
        except Exception as e:
            s = {
                'stack_aggregator': 'unexpected error',
                'external_request_id': input_json.get('external_request_id'),
                'message': '%s' % e
            }

    return flask.jsonify(s)


if __name__ == "__main__":
    app.run()

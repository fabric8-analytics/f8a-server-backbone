import flask
from flask import Flask, request
from flask_cors import CORS
from recommender import RecommendationTask
from stack_aggregator import StackAggregator
from stack_recommender import StackRecommender

app = Flask(__name__)
CORS(app)


@app.route('/api/v1/readiness')
def readiness():
    return flask.jsonify({}), 200


@app.route('/api/v1/liveness')
def liveness():
    return flask.jsonify({}), 200


@app.route('/api/v1/stack-recommender', methods=['POST'])
def stack_recommender():
    input_json = request.get_json()
    if input_json and 'external_request_id' in input_json and input_json['external_request_id']:
        try:
            persist = request.args.get('persist', 'true') == 'true'
            r = StackRecommender().execute(input_json, persist)
            status = 200
        except Exception as e:
            r = {
                'status': 'unexpected error',
                'external_request_id': input_json.get('external_request_id'),
                'message': '%s' % e
            }
            status = 500

    return flask.jsonify(r), status


@app.route('/api/v1/recommender', methods=['POST'])
def recommender():
    r = {'recommendation': 'failure', 'external_request_id': None}
    status = 400
    input_json = request.get_json()
    if input_json and 'external_request_id' in input_json and input_json['external_request_id']:
        try:
            r = RecommendationTask().execute(input_json)
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
    s = {'stack_aggregator': 'failure', 'external_request_id': None}
    input_json = request.get_json()
    if input_json and 'external_request_id' in input_json and input_json['external_request_id']:
        try:
            s = StackAggregator().execute(input_json)
        except Exception as e:
            s = {
                'stack_aggregator': 'unexpected error',
                'external_request_id': input_json.get('external_request_id'),
                'message': '%s' % e
            }

    return flask.jsonify(s)


if __name__ == "__main__":
    app.run()

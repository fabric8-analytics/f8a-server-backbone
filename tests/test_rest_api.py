"""Tests for the REST API of the backbone service."""
import json
from unittest import mock
from tests.v2.test_stack_aggregator import _request_body

response = {
    "recommendation": "success",
    "external_request_id": "some_external_request_id",
    "result": {
        "recommendations": [
            {"companion": [],
             "alternate": [],
             "usage_outliers": [],
             "manifest_file_path": "/home/JohnDoe",
             "input_stack_topics": {
                 "io.vertx:vertx-core": ["http", "socket", "cluster", "reactive"],
                 "io.vertx:vertx-web": ["event-bus", "jwt", "webapp", "routing"]},
             "missing_packages_pgm": []
             }],
        "_audit": {
            "started_at": "2018-11-16T13:24:26.058219",
            "ended_at": "2018-11-16T13:24:26.059321",
            "version": "v1"
        },
        "_release": "None:None:None"}}


class Response2:
    """Fake Response2."""

    status_code = 200

    @staticmethod
    def json():
        """Json Response."""
        return response


def get_json_from_response(response):
    """Decode JSON from response."""
    return json.loads(response.data.decode('utf8'))


def test_readiness_endpoint(client):
    """Test the /api/readiness endpoint."""
    response = client.get("/api/readiness")
    assert response.status_code == 200
    json_data = get_json_from_response(response)
    assert json_data == {}, "Empty JSON response expected"


def test_liveness_endpoint(client):
    """Test the /api/liveness endpoint."""
    response = client.get("/api/liveness")
    assert response.status_code == 200
    json_data = get_json_from_response(response)
    assert json_data == {}, "Empty JSON response expected"


@mock.patch('src.v2.stack_aggregator.StackAggregator.execute', return_value=response)
def test_stack_api_endpoint(_mock, client):
    """Check the /stack_aggregator REST API endpoint."""
    stack_resp = client.post("/api/v2/stack_aggregator",
                             data=json.dumps(_request_body()),
                             content_type='application/json')
    _mock.assert_called_once()
    jsn = get_json_from_response(stack_resp)
    assert jsn['external_request_id'] is not None


@mock.patch('src.v2.recommender.RecommendationTask.execute', return_value=response)
def test_recommendation_api_endpoint(_mock_object, client):
    """Check the /recommender REST API endpoint."""
    rec_resp = client.post("/api/v2/recommender",
                           data=json.dumps(_request_body()), content_type='application/json')
    _mock_object.assert_called_once()
    jsn = get_json_from_response(rec_resp)
    assert jsn['recommendation'] == 'success'
    assert jsn['external_request_id'] is not None

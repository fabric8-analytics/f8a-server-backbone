"""Tests for the REST API of the backbone service."""

import requests
import os
import json
from unittest import mock

payload = {
    "external_request_id": "req-id",
    "result": [{
        "summary": [],
        "details": [{
            "ecosystem": "maven",
            "description": "Exposes an HTTP API using Vert.x",
            "_resolved": [{
                "package": "io.vertx:vertx-web",
                "version": "3.4.2"
            }, {
                "package": "io.vertx:vertx-core",
                "version": "3.4.2"
            }],
            "manifest_file_path": "/home/JohnDoe",
            "manifest_file": "pom.xml",
            "declared_licenses": ["Apache License, Version 2.0"],
            "name": "Vert.x - HTTP",
            "dependencies": ["io.vertx:vertx-web 3.4.2", "io.vertx:vertx-core 3.4.2"],
            "version": "1.0.0-SNAPSHOT",
            "devel_dependencies": [
                "com.jayway.restassured:rest-assured 2.9.0",
                "io.openshift:openshift-test-utils 2",
                "org.assertj:assertj-core 3.6.2", "junit:junit 4.12",
                "io.vertx:vertx-unit 3.4.2", "io.vertx:vertx-web-client 3.4.2",
                "com.jayway.awaitility:awaitility 1.7.0"], "homepage": None
        }],
        "status": "success"
    }]
}
port = os.getenv("API_BACKBONE_SERVICE_PORT", "5000")
url = "http://localhost:{port}/api/v1".format(port=port)
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


def get_json_from_response(response):
    """Decode JSON from response."""
    return json.loads(response.data.decode('utf8'))


def api_route_for(route):
    """Construct an URL to the endpoint for given route."""
    return '/api/v1/' + route


def test_readiness_endpoint(client):
    """Test the /api/v1/readiness endpoint."""
    response = client.get(api_route_for("readiness"))
    assert response.status_code == 200
    json_data = get_json_from_response(response)
    assert json_data == {}, "Empty JSON response expected"


def test_liveness_endpoint(client):
    """Test the /api/v1/liveness endpoint."""
    response = client.get(api_route_for("liveness"))
    assert response.status_code == 200
    json_data = get_json_from_response(response)
    assert json_data == {}, "Empty JSON response expected"


# def test_stack_api_endpoint():
#     """Check the /stack_aggregator REST API endpoint."""
#     stack_resp = requests.post(url + "/stack_aggregator", json=payload)
#     jsn = stack_resp.json()
#     assert jsn['external_request_id'] is not None


@mock.patch('src.recommender.RecommendationTask.execute', side_effect=response)
def test_recommendation_api_endpoint(_mock_object, client):
    """Check the /recommender REST API endpoint."""
    rec_resp = client.post(api_route_for("recommender"),
                           data=json.dumps(payload), content_type='application/json')
    jsn = get_json_from_response(rec_resp)
    assert jsn['recommendation'] == 'pgm_error'
    assert jsn['external_request_id'] is not None


if __name__ == '__main__':
    test_readiness_endpoint()
    test_liveness_endpoint()
    test_stack_api_endpoint()
    test_recommendation_api_endpoint()

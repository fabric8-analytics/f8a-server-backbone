"""Tests for the REST API of the backbone service."""
import json
from unittest import mock

from src.v2.models import RecommenderRequest, Package
from tests.v2.data import (
    npm_insights_response_for_request,
    graph_package_response_for_npm_express_winston,
)


def get_json_from_response(response):
    """Decode JSON from response."""
    response = json.loads(response.data.decode("utf8"))
    assert response["result"]["_audit"] is not None
    # delete _audit field as it has time value which is not assertable
    del response["result"]["_audit"]
    return response


def test_invalid_request_payload(client):
    """Test invalid request payload."""
    response = client.post(
        "/api/v2/recommender", data=json.dumps({}), content_type="application/json"
    )
    assert response.status_code == 500


def test_golang_empty_response(client):
    """Test golang ecosystem, it should return empty result."""
    response = client.post(
        "/api/v2/recommender",
        data=json.dumps(
            RecommenderRequest(
                registration_status="",
                external_request_id="",
                ecosystem="golang",
                manifest_file_path="",
                packages=[],
            ).dict()
        ),
        content_type="application/json",
    )
    assert response.status_code == 200
    json_val = json.loads(response.data.decode("utf8"))
    assert json_val == {}


class _Response:
    """Mock Response."""

    def __init__(self, code, json):
        self.status_code = code
        self._json = json

    def json(self):
        """Json Response."""
        return self._json

    def raise_for_status(self):
        if self.status_code != 200:
            raise Exception("not 200")


@mock.patch("src.v2.recommender.post_gremlin", return_value={"result": {"data": []}})
@mock.patch("requests.Session.post", return_value=_Response(404, {}))
def test_recommendation_response_with_insight_error(
    _mock_insight_response, _mock_gremlin, client
):
    """Test golang ecosystem, it should return empty result."""
    response = client.post(
        "/api/v2/recommender?persist=false",
        data=json.dumps(
            RecommenderRequest(
                registration_status="",
                external_request_id="",
                ecosystem="npm",
                manifest_file_path="",
                packages=[Package(name="request", version="2.88.2")],
            ).dict()
        ),
        content_type="application/json",
    )
    assert response.status_code == 500


@mock.patch("src.v2.recommender.post_gremlin", return_value={"result": {"data": []}})
@mock.patch("requests.Session.post", return_value=_Response(404, {}))
def test_recommendation_response_with_empty_package_request(
    _mock_insight_response, _mock_gremlin, client
):
    """Test with empty package list."""
    response = client.post(
        "/api/v2/recommender?persist=false",
        data=json.dumps(
            RecommenderRequest(
                registration_status="FREETIER",
                external_request_id="foo",
                ecosystem="npm",
                manifest_file_path="/foo.bar",
                packages=[],
            ).dict()
        ),
        content_type="application/json",
    )
    assert response.status_code == 500


@mock.patch("src.v2.recommender.post_gremlin", return_value={"result": {"data": []}})
@mock.patch(
    "requests.Session.post",
    return_value=_Response(
        200,
        [
            {
                "companion_packages": [],
                "ecosystem": "npm",
                "missing_packages": ["blala"],
                "package_to_topic_dict": {},
            }
        ],
    ),
)
@mock.patch("src.v2.recommender.persist_data_in_db")
def test_recommendation_response_with_empty_insight_response(
    _mock_insight_response, _mock_gremlin, _mock_persist_db, client
):
    """Test with empty recommender response."""
    response = client.post(
        "/api/v2/recommender?persist=true",
        data=json.dumps(
            RecommenderRequest(
                registration_status="FREETIER",
                external_request_id="foo",
                ecosystem="npm",
                manifest_file_path="/foo.bar",
                packages=[Package(name="blala", version="1.000")],
            ).dict()
        ),
        content_type="application/json",
    )
    assert response.status_code == 200
    response = get_json_from_response(response)
    assert response == {
        "external_request_id": "foo",
        "recommendation": "success",
        "result": {
            "companion": [],
            "external_request_id": "foo",
            "manifest_file_path": "/foo.bar",
            "manifest_name": None,
            "recommendation_status": "success",
            "registration_status": "FREETIER",
            "usage_outliers": [],
            "uuid": None,
        },
    }


@mock.patch("src.v2.recommender.post_gremlin", return_value={"result": {"data": []}})
@mock.patch(
    "requests.Session.post",
    return_value=_Response(
        200,
        npm_insights_response_for_request.DATA,
    ),
)
def test_recommendation_response_with_empty_graph(
    _mock_insight_response, _mock_gremlin, client
):
    """Test with empty graph response."""
    response = client.post(
        "/api/v2/recommender?persist=false",
        data=json.dumps(
            RecommenderRequest(
                registration_status="FREETIER",
                external_request_id="foo",
                ecosystem="npm",
                manifest_file_path="/foo.bar",
                packages=[Package(name="request", version="2.88.2")],
            ).dict()
        ),
        content_type="application/json",
    )
    assert response.status_code == 200
    response = get_json_from_response(response)
    assert response["result"] == {
        "companion": [],
        "external_request_id": "foo",
        "manifest_file_path": "/foo.bar",
        "manifest_name": None,
        "recommendation_status": "success",
        "registration_status": "FREETIER",
        "usage_outliers": [],
        "uuid": None,
    }


@mock.patch(
    "src.v2.recommender.post_gremlin",
    return_value=graph_package_response_for_npm_express_winston.DATA,
)
@mock.patch(
    "requests.Session.post",
    return_value=_Response(
        200,
        npm_insights_response_for_request.DATA,
    ),
)
def test_recommendation_response_with_2_packages_from_graph(
    _mock_insight_response, _mock_gremlin, client
):
    """Test for happy scenario."""
    response = client.post(
        "/api/v2/recommender?persist=false",
        data=json.dumps(
            RecommenderRequest(
                registration_status="FREETIER",
                external_request_id="foo",
                ecosystem="npm",
                manifest_file_path="/foo.bar",
                packages=[Package(name="request", version="2.88.2")],
            ).dict()
        ),
        content_type="application/json",
    )
    assert response.status_code == 200
    response = get_json_from_response(response)
    assert response["result"] == {
        "companion": [
            {
                "cooccurrence_count": 0,
                "cooccurrence_probability": 52.50463667254613,
                "dependencies": None,
                "ecosystem": "npm",
                "github": {
                    "contributors": "238",
                    "dependent_projects": "48988",
                    "dependent_repos": "893994",
                    "forks_count": "8571",
                    "issues": {
                        "month": {"closed": 18, "opened": 18},
                        "year": {"closed": -1, "opened": -1},
                    },
                    "latest_release_duration": "2018-10-27 03:12:11",
                    "open_issues_count": "155",
                    "pull_requests": {
                        "month": {"closed": 0, "opened": 3},
                        "year": {"closed": 61, "opened": 75},
                    },
                    "size": "N/A",
                    "stargazers_count": "51280",
                    "total_releases": "291",
                    "used_by": [
                        {"name": "Automattic/mongoose", "stars": "14372"},
                        {"name": "ReactTraining/react-router", "stars": "27232"},
                        {"name": "angular/angular.js", "stars": "57749"},
                        {"name": "angular/angular", "stars": "31547"},
                        {"name": "facebook/jest", "stars": "14465"},
                        {"name": "facebook/react", "stars": "84669"},
                        {"name": "postcss/autoprefixer", "stars": "14331"},
                        {"name": "reactjs/redux", "stars": "36922"},
                        {"name": "socketio/socket.io", "stars": "38209"},
                        {"name": "webpack/webpack", "stars": "35429"},
                    ],
                    "watchers": "1799",
                },
                "latest_version": "4.17.1",
                "licenses": [],
                "name": "express",
                "topic_list": ["accepts"],
                "url": "https://snyk.io/vuln/npm:express",
                "version": "4.17.1",
            }
        ],
        "external_request_id": "foo",
        "manifest_file_path": "/foo.bar",
        "manifest_name": None,
        "recommendation_status": "success",
        "registration_status": "FREETIER",
        "usage_outliers": [],
        "uuid": None,
    }

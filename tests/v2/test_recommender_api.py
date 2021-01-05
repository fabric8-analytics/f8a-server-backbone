"""Tests for the REST API of the backbone service."""
import json
from unittest import mock

from src.v2.models import RecommenderRequest, Package


def get_json_from_response(response):
    """Decode JSON from response."""
    response = json.loads(response.data.decode("utf8"))
    assert response["result"]["_audit"] is not None
    # delete _audit field as it has time value which is not assertable
    del response["result"]["_audit"]
    return response


def test_invalid_request_payload(client):
    """Test the /api/readiness endpoint."""
    response = client.post(
        "/api/v2/recommender", data=json.dumps({}), content_type="application/json"
    )
    assert response.status_code == 500


def test_golang_empty_response(client):
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


@mock.patch("src.v2.recommender_v2.post_gremlin", return_value={"result": {"data": []}})
@mock.patch("requests.Session.post", return_value=_Response(404, {}))
def test_npm_recommendation_response_with_insight_error(
    _mock_insight_response, _mock_gremlin, client
):
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


@mock.patch("src.v2.recommender_v2.post_gremlin", return_value={"result": {"data": []}})
@mock.patch("requests.Session.post", return_value=_Response(404, {}))
def test_npm_recommendation_response_with_empty_package_request(
    _mock_insight_response, _mock_gremlin, client
):
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


@mock.patch("src.v2.recommender_v2.post_gremlin", return_value={"result": {"data": []}})
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
@mock.patch("src.v2.recommender_v2.persist_data_in_db")
def test_npm_recommendation_response_with_empty_insight_response(
    _mock_insight_response, _mock_gremlin, _mock_persist_db, client
):
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


@mock.patch("src.v2.recommender_v2.post_gremlin", return_value={"result": {"data": []}})
@mock.patch(
    "requests.Session.post",
    return_value=_Response(
        200,
        [
            {
                "companion_packages": [
                    {
                        "cooccurrence_probability": 52.50463667254613,
                        "package_name": "express",
                        "topic_list": [
                            "accepts",
                        ],
                    },
                    {
                        "cooccurrence_probability": 51.04134789351682,
                        "package_name": "winston",
                        "topic_list": [
                            "async",
                        ],
                    },
                    {
                        "cooccurrence_probability": 49.54337206255131,
                        "package_name": "moment",
                        "topic_list": [],
                    },
                    {
                        "cooccurrence_probability": 49.18425744667468,
                        "package_name": "colors",
                        "topic_list": [],
                    },
                    {
                        "cooccurrence_probability": 47.72579254602449,
                        "package_name": "commander",
                        "topic_list": [],
                    },
                ],
                "ecosystem": "npm",
                "missing_packages": [],
                "package_to_topic_dict": {
                    "request": [
                        "aws-sign2",
                    ]
                },
            }
        ],
    ),
)
def test_npm_recommendation_response_with_empty_graph(
    _mock_insight_response, _mock_gremlin, client
):
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
                "github": None,
                "latest_version": "n/a",
                "licenses": None,
                "name": "express",
                "topic_list": ["accepts"],
                "url": None,
                "version": "n/a",
            },
            {
                "cooccurrence_count": 0,
                "cooccurrence_probability": 51.04134789351682,
                "dependencies": None,
                "ecosystem": "npm",
                "github": None,
                "latest_version": "n/a",
                "licenses": None,
                "name": "winston",
                "topic_list": ["async"],
                "url": None,
                "version": "n/a",
            },
            {
                "cooccurrence_count": 0,
                "cooccurrence_probability": 49.54337206255131,
                "dependencies": None,
                "ecosystem": "npm",
                "github": None,
                "latest_version": "n/a",
                "licenses": None,
                "name": "moment",
                "topic_list": [],
                "url": None,
                "version": "n/a",
            },
            {
                "cooccurrence_count": 0,
                "cooccurrence_probability": 49.18425744667468,
                "dependencies": None,
                "ecosystem": "npm",
                "github": None,
                "latest_version": "n/a",
                "licenses": None,
                "name": "colors",
                "topic_list": [],
                "url": None,
                "version": "n/a",
            },
            {
                "cooccurrence_count": 0,
                "cooccurrence_probability": 47.72579254602449,
                "dependencies": None,
                "ecosystem": "npm",
                "github": None,
                "latest_version": "n/a",
                "licenses": None,
                "name": "commander",
                "topic_list": [],
                "url": None,
                "version": "n/a",
            },
        ],
        "external_request_id": "foo",
        "manifest_file_path": "/foo.bar",
        "manifest_name": None,
        "recommendation_status": "success",
        "registration_status": "FREETIER",
        "usage_outliers": [],
        "uuid": None,
    }


@mock.patch(
    "src.v2.recommender_v2.post_gremlin",
    return_value={
        "result": {
            "data": [
                {
                    "gh_issues_last_month_opened": [18],
                    "gh_prs_last_year_closed": [61],
                    "libio_usedby": [
                        "Automattic/mongoose:14372",
                        "ReactTraining/react-router:27232",
                        "angular/angular.js:57749",
                        "angular/angular:31547",
                        "facebook/jest:14465",
                        "facebook/react:84669",
                        "postcss/autoprefixer:14331",
                        "reactjs/redux:36922",
                        "socketio/socket.io:38209",
                        "webpack/webpack:35429",
                    ],
                    "ecosystem": ["npm"],
                    "gh_subscribers_count": [1799],
                    "gh_contributors_count": [238],
                    "latest_version_last_updated": ["20201120"],
                    "vertex_label": ["Package"],
                    "libio_dependents_repos": ["893994"],
                    "latest_non_cve_version": ["4.17.1"],
                    "gh_issues_last_year_opened": [-1],
                    "gh_issues_last_month_closed": [18],
                    "gh_open_issues_count": [155],
                    "libio_dependents_projects": ["48988"],
                    "latest_version": ["4.17.1"],
                    "tokens": ["express"],
                    "package_relative_used": ["not used"],
                    "gh_stargazers": [51280],
                    "gh_forks": [8571],
                    "package_dependents_count": [-1],
                    "gh_prs_last_month_opened": [3],
                    "gh_issues_last_year_closed": [-1],
                    "last_updated": [1.6087431764215431e9],
                    "gh_prs_last_month_closed": [0],
                    "topics": ["express", "javascript", "nodejs", "server"],
                    "libio_total_releases": ["291"],
                    "gh_refreshed_on": ["2020-12-23 16:28:34"],
                    "gh_prs_last_year_opened": [75],
                    "name": ["express"],
                    "libio_latest_version": ["5.0.0-alpha.7"],
                    "libio_latest_release": [1.540609931e9],
                },
                {
                    "gh_issues_last_month_opened": [-1],
                    "gh_prs_last_year_closed": [-1],
                    "libio_usedby": [
                        "amir20/phantomjs-node:2884",
                        "angular/angular.js:56712",
                        "angular/angular:26987",
                        "angular/material2:10337",
                        "apidoc/apidoc:4685",
                        "cyclejs/cyclejs:7180",
                        "flatiron/prompt:1142",
                        "foreverjs/forever:9868",
                        "ionic-team/ionic-native:1384",
                        "ionic-team/ionic:30889",
                    ],
                    "ecosystem": ["npm"],
                    "gh_subscribers_count": [224],
                    "gh_contributors_count": [30],
                    "vertex_label": ["Package"],
                    "libio_dependents_repos": ["35152"],
                    "gh_issues_last_year_opened": [-1],
                    "gh_issues_last_month_closed": [-1],
                    "gh_open_issues_count": [236],
                    "libio_dependents_projects": ["6413"],
                    "latest_version": ["3.2.1"],
                    "tokens": ["winston"],
                    "package_relative_used": ["not used"],
                    "gh_stargazers": [12020],
                    "gh_forks": [1129],
                    "package_dependents_count": [-1],
                    "gh_prs_last_month_opened": [-1],
                    "gh_issues_last_year_closed": [-1],
                    "last_updated": [1.560302668156725e9],
                    "gh_prs_last_month_closed": [-1],
                    "libio_total_releases": ["73"],
                    "gh_prs_last_year_opened": [-1],
                    "name": ["winston"],
                    "libio_latest_version": ["3.0.0"],
                    "libio_latest_release": [1.528821086e9],
                },
            ],
        }
    },
)
@mock.patch(
    "requests.Session.post",
    return_value=_Response(
        200,
        [
            {
                "companion_packages": [
                    {
                        "cooccurrence_probability": 52.50463667254613,
                        "package_name": "express",
                        "topic_list": [
                            "accepts",
                        ],
                    },
                    {
                        "cooccurrence_probability": 51.04134789351682,
                        "package_name": "winston",
                        "topic_list": [
                            "async",
                        ],
                    },
                    {
                        "cooccurrence_probability": 49.54337206255131,
                        "package_name": "moment",
                        "topic_list": [],
                    },
                    {
                        "cooccurrence_probability": 49.18425744667468,
                        "package_name": "colors",
                        "topic_list": [],
                    },
                    {
                        "cooccurrence_probability": 47.72579254602449,
                        "package_name": "commander",
                        "topic_list": [],
                    },
                ],
                "ecosystem": "npm",
                "missing_packages": [],
                "package_to_topic_dict": {
                    "request": [
                        "aws-sign2",
                    ]
                },
            }
        ],
    ),
)
def test_npm_recommendation_response_with_2_packages_from_graph(
    _mock_insight_response, _mock_gremlin, client
):
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
                    "first_release_date": "Apr 16, 2010",
                    "forks_count": "8571",
                    "issues": {
                        "month": {"closed": 18, "opened": 18},
                        "year": {"closed": -1, "opened": -1},
                    },
                    "latest_release_duration": "2018-10-27 08:42:11",
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
                    "watchers": None,
                },
                "latest_version": "4.17.1",
                "licenses": [],
                "name": "express",
                "topic_list": ["accepts"],
                "url": "https://snyk.io/vuln/npm:express",
                "version": "4.17.1",
            },
            {
                "cooccurrence_count": 0,
                "cooccurrence_probability": 51.04134789351682,
                "dependencies": None,
                "ecosystem": "npm",
                "github": {
                    "contributors": "30",
                    "dependent_projects": "6413",
                    "dependent_repos": "35152",
                    "first_release_date": "Apr 16, 2010",
                    "forks_count": "1129",
                    "issues": {
                        "month": {"closed": -1, "opened": -1},
                        "year": {"closed": -1, "opened": -1},
                    },
                    "latest_release_duration": "2018-06-12 22:01:26",
                    "open_issues_count": "236",
                    "pull_requests": {
                        "month": {"closed": -1, "opened": -1},
                        "year": {"closed": -1, "opened": -1},
                    },
                    "size": "N/A",
                    "stargazers_count": "12020",
                    "total_releases": "73",
                    "used_by": [
                        {"name": "amir20/phantomjs-node", "stars": "2884"},
                        {"name": "angular/angular.js", "stars": "56712"},
                        {"name": "angular/angular", "stars": "26987"},
                        {"name": "angular/material2", "stars": "10337"},
                        {"name": "apidoc/apidoc", "stars": "4685"},
                        {"name": "cyclejs/cyclejs", "stars": "7180"},
                        {"name": "flatiron/prompt", "stars": "1142"},
                        {"name": "foreverjs/forever", "stars": "9868"},
                        {"name": "ionic-team/ionic-native", "stars": "1384"},
                        {"name": "ionic-team/ionic", "stars": "30889"},
                    ],
                    "watchers": None,
                },
                "latest_version": "3.2.1",
                "licenses": [],
                "name": "winston",
                "topic_list": ["async"],
                "url": "https://snyk.io/vuln/npm:winston",
                "version": "",
            },
            {
                "cooccurrence_count": 0,
                "cooccurrence_probability": 49.54337206255131,
                "dependencies": None,
                "ecosystem": "npm",
                "github": None,
                "latest_version": "n/a",
                "licenses": None,
                "name": "moment",
                "topic_list": [],
                "url": None,
                "version": "n/a",
            },
            {
                "cooccurrence_count": 0,
                "cooccurrence_probability": 49.18425744667468,
                "dependencies": None,
                "ecosystem": "npm",
                "github": None,
                "latest_version": "n/a",
                "licenses": None,
                "name": "colors",
                "topic_list": [],
                "url": None,
                "version": "n/a",
            },
            {
                "cooccurrence_count": 0,
                "cooccurrence_probability": 47.72579254602449,
                "dependencies": None,
                "ecosystem": "npm",
                "github": None,
                "latest_version": "n/a",
                "licenses": None,
                "name": "commander",
                "topic_list": [],
                "url": None,
                "version": "n/a",
            },
        ],
        "external_request_id": "foo",
        "manifest_file_path": "/foo.bar",
        "manifest_name": None,
        "recommendation_status": "success",
        "registration_status": "FREETIER",
        "usage_outliers": [],
        "uuid": None,
    }

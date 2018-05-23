"""Tests for the recommender module."""
from unittest import TestCase
from unittest import mock
import json
import logging
logger = logging.getLogger(__name__)

from recommender import RecommendationTask, GraphDB
from rest_api import app


def mocked_requests_get(*args, **kwargs):
    """Mock the call to the insights service."""
    class MockResponse:
        """Mock response object."""

        def __init__(self, json_data, status_code):
            """Create a mock json response."""
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            """Get the mock json response."""
            return self.json_data

    # return the URL to check whether we are calling the correct service.
    return MockResponse({"url": args[0]}, 200)


class TestRecommendationTask(TestCase):
    """Tests for the recommendation task class."""

    @mock.patch('requests.get', side_effect=mocked_requests_get)
    @mock.patch('requests.Session.post', side_effect=mocked_requests_get)
    def test_call_insights_recommender_npm(self, mock_get, mock_post):
        """Test if the correct service is called for the correct ecosystem."""
        with app.app_context():
            # Test whether the correct service is called for NPM.
            called_url_json = RecommendationTask.call_insights_recommender([{
                "ecosystem": "npm"
            }])
            self.assertTrue('npm-insights' in called_url_json['url'])
            # Now test whether the correct service is called for maven.
            called_url_json = RecommendationTask.call_insights_recommender([{
                "ecosystem": "maven"
            }])
            self.assertTrue('pgm' in called_url_json['url'])


def test_execute():
    f = open("tests/data/stack_aggregator_execute_input.json", "r")
    payload = json.loads(f.read())

    r = RecommendationTask()
    out = r.execute(arguments=payload,persist=False,unit_test=True)
    assert(out['recommendation'] == "success")

    r = RecommendationTask()
    out = r.execute(arguments=payload, check_license=True, persist=False, unit_test=True)
    assert (out['recommendation'] == "success")


def test_filter_versions():
    input_stack = {"io.vertx:vertx-web": "3.4.2", "io.vertx:vertx-core": "3.4.2"}

    f = open("tests/data/companion_pkg_graph.json", "r")
    companion_packages_graph = json.loads(f.read())

    g = GraphDB()
    filtered_comp_packages_graph, filtered_list = g.filter_versions(companion_packages_graph,
                                                                    input_stack)
    assert (len(filtered_comp_packages_graph) > 0)
    assert (len(filtered_list) > 0)


if __name__ == '__main__':
    test_execute()
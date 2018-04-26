"""Tests for the recommender module."""
from unittest import TestCase
from unittest import mock
import logging
logger = logging.getLogger(__name__)

from recommender import RecommendationTask
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

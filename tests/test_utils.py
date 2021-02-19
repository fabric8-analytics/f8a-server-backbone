"""Tests for the 'utils' module."""
import os
from unittest import mock
from pytest import raises
from tests.test_rest_api import response
from src.settings import SETTINGS
from src.utils import push_data, get_time_delta
from src.utils import (
    format_date,
    post_http_request,
    select_from_db, total_time_elapsed, post_gremlin,
    GremlinExeception, RequestException)

METRICS_COLLECTION_URL = "http://{base_url}:{port}/api/v1/prometheus".format(
    base_url='metrics-accumulator-deepak1725-fabric8-analytics.devtools-dev.ext.devshift.net',
    port=80)


def mock_error_response(*_args, **_kwargs):
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

        def raise_for_status(self):
            if self.status_code != 200:
                raise Exception('not 200')

    return MockResponse({}, 500)


def mock_get_osio_user_count(*_args, **_kwargs):
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

        def raise_for_status(self):
            if self.status_code != 200:
                raise Exception('not 200')

    # return the URL to check whether we are calling the correct service.
    resp = {
        "requestId": "f98d1366-738e-4c14-a3ff-594f359e131c",
        "status": {
            "message": "",
            "code": 200,
            "attributes": {}
        },
        "result": {
            "data": [
                0
            ],
            "meta": {}
        }
    }
    return MockResponse(resp, 200)


def test_format_date():
    """Check the function format_date()."""
    date1 = '2019-05-21 06:44:15'
    date2 = 'N/A'
    date3 = 'None'
    date4 = 'Blah Blah'
    assert format_date(date1) == '21 May 2019'
    assert format_date(date2) == 'N/A'
    assert format_date(date3) == 'N/A'
    assert format_date(date4) == 'N/A'


@mock.patch('requests.Session.post', side_effect=mock_error_response)
def test_post_http_request(_mock1):
    """Test error response for gremlin."""
    payload = {'gremlin': ''}
    with raises(RequestException):
        post_http_request(url=SETTINGS.gremlin_url, payload=payload)


def test_select_from_db():
    """Test Select from DB."""
    sf_db = select_from_db(external_request_id="req-id", worker="recommendation_v2")
    assert 'recommendation' in sf_db.keys()
    assert 'message' in sf_db.keys()
    assert sf_db.get('status') == 501
    assert sf_db.get('external_request_id') == 'req-id'


@mock.patch('src.utils.select_from_db', return_value=None)
def test_total_time_elapsed(_mock1):
    """Check Total Time Elapsed Method."""
    timedelta = total_time_elapsed(
        sa_audit_data=response["result"]["_audit"],
        external_request_id=response["external_request_id"],
    )
    assert timedelta is not None


@mock.patch('src.utils.select_from_db', return_value=None)
def test_total_time_elapsed_no_param(_mock1):
    """Test Select from DB."""
    sf_db = total_time_elapsed(sa_audit_data={}, external_request_id="req-id")
    assert sf_db is None


def test_push_data():
    """Check the Push Data Method."""
    metrics_payload = {
        'pid': os.getpid(),
        'hostname': os.environ.get("HOSTNAME"),
        'endpoint': "pi_v1.test__slashless",
        'request_method': "GET",
        'status_code': 200,
        'value': 0.001,
    }
    response_obj = push_data(metrics_payload, url=METRICS_COLLECTION_URL)
    assert response_obj is None


def test_get_time_delta():
    """Check the Push Data Method."""
    timedelta = get_time_delta(audit_data=response['result']['_audit'])
    assert timedelta == 0.001102


def test_get_time_delta_with_no_param():
    """Check the Push Data Method."""
    assert get_time_delta({}) is None


@mock.patch('requests.Session.post', side_effect=mock_error_response)
def test_post_gremlin_exception(_mock_post):
    """Test error response for gremlin."""
    with raises(GremlinExeception):
        post_gremlin(query='gremlin_quey', bindings={'val': 123})


@mock.patch('requests.Session.post', side_effect=mock_get_osio_user_count)
def test_post_gremlin_normal(_mock_post):
    """Test error response for gremlin."""
    post_gremlin(query='gremlin_query', bindings={'val': 123})
    _mock_post.assert_called_once()
    kwargs = _mock_post.call_args_list[0][1]['json']
    assert kwargs['gremlin'] == 'gremlin_query'
    assert kwargs['bindings'] == {'val': 123}

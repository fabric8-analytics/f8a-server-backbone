"""Tests for the 'utils' module."""
import os
import json
import semantic_version as sv
from unittest import mock
from pytest import raises
from tests.test_rest_api import response
from src.utils import push_data, get_time_delta
from src.utils import (
    convert_version_to_proper_semantic as cvs, GREMLIN_SERVER_URL_REST, format_date,
    version_info_tuple as vt, select_latest_version as slv,
    get_osio_user_count, create_package_dict, is_quickstart_majority, post_http_request,
    server_create_analysis, select_from_db, total_time_elapsed, post_gremlin,
    GremlinExeception)

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


def test_semantic_versioning():
    """Check the function cvs()."""
    package_name = "test_package"
    version = "-1"
    assert cvs(version, package_name) == sv.Version("0.0.0")
    version = ""
    assert cvs(version, package_name) == sv.Version("0.0.0")
    version = None
    assert cvs(version, package_name) == sv.Version("0.0.0")
    version = "1.5.2.RELEASE"
    assert cvs(version, package_name) == sv.Version("1.5.2+RELEASE")
    version = "1.5-2.RELEASE"
    assert cvs(version, package_name) == sv.Version("1.5.2+RELEASE")
    version = "2"
    assert cvs(version, package_name) == sv.Version("2.0.0")
    version = "2.3"
    assert cvs(version, package_name) == sv.Version("2.3.0")
    version = "2.0.rc1"
    assert cvs(version, package_name) == sv.Version("2.0.0+rc1")
    version = "[1.4)"
    assert cvs(version, package_name) == sv.Version("0.0.0")


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


def test_version_info_tuple():
    """Check the function vt()."""
    # TODO: reduce cyclomatic complexity
    version_str = "2.0.rc1"
    package_name = "test_package"
    version_obj = cvs(version_str, package_name)
    version_info = vt(version_obj)
    assert len(version_info) == 4
    assert version_info[0] == version_obj.major
    assert version_info[1] == version_obj.minor
    assert version_info[2] == version_obj.patch
    assert version_info[3] == version_obj.build
    version_obj = ""
    version_info = vt(version_obj)
    assert len(version_info) == 4
    assert version_info[0] == 0
    assert version_info[1] == 0
    assert version_info[2] == 0
    assert version_info[3] == tuple()


def test_select_latest_version():
    """Check fucntion slv()."""
    input_version = "1.2.2"
    libio = "1.2.3"
    anitya = "1.3.4"
    package_name = "test_package"
    result_version = slv(input_version, libio, anitya, package_name)
    assert result_version == anitya
    input_version = ""
    libio = ""
    anitya = ""
    result_version = slv(input_version, libio, anitya, package_name)
    assert result_version == ""


@mock.patch('requests.get', side_effect=mock_get_osio_user_count)
@mock.patch('requests.Session.post', side_effect=mock_get_osio_user_count)
def test_get_osio_user_count(_mock_get, _mock_post):
    """Test the function get_osio_user_count."""
    out = get_osio_user_count("maven", "io.vertx:vertx-core", "3.4.2")
    assert isinstance(out, int)


@mock.patch('src.utils.get_osio_user_count', return_value=1)
def test_create_package_dict(_mock_count):
    """Test the function get_osio_user_count."""
    with open('tests/data/companion_pkg_graph.json', 'r') as f:
        resp = json.loads(f.read())
    out = create_package_dict(resp)
    assert len(out) > 1


def test_is_quickstart_majority():
    """Test the function is_quickstart_majority."""
    package_list = []
    assert is_quickstart_majority(package_list)
    package_list = ['io.vertx:vertx-core',
                    'org.springframework.boot:spring-boot-starter-web',
                    'org.slf4j:slf4j-api']
    assert is_quickstart_majority(package_list)
    package_list = ['org.slf4j:slf4j-api']
    assert not is_quickstart_majority(package_list)


@mock.patch('requests.Session.post', side_effect=mock_error_response)
def test_post_http_request(_mock1):
    """Test error response for gremlin."""
    payload = {'gremlin': ''}
    result = post_http_request(url=GREMLIN_SERVER_URL_REST, payload=payload)
    assert result is None


def test_server_create_analysis():
    """Test server_create_analysis."""
    rec_resp = server_create_analysis("npm", "hjhjhjh", "1.1")
    assert rec_resp is None


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

@mock.patch('requests.Session.post', return_value=None)
def test_post_gremlin_exception(_mock_post):
    """Test error response for gremlin."""
    with raises(GremlinExeception):
        post_gremlin(query='gremlin_quey', bindings={'val': 123})

@mock.patch('requests.Session.post', side_effect=mock_get_osio_user_count)
def test_post_gremlin_normal(_mock_post):
    """Test error response for gremlin."""
    response = post_gremlin(query='gremlin_query', bindings={'val': 123})
    _mock_post.assert_called_once()
    kwargs = _mock_post.call_args_list[0][1]['json']
    assert kwargs['gremlin'] == 'gremlin_query'
    assert kwargs['bindings'] == {'val': 123}

if __name__ == '__main__':
    test_semantic_versioning()
    test_version_info_tuple()
    test_select_latest_version()
    test_get_osio_user_count()
    test_is_quickstart_majority()
    test_post_http_request()
    test_create_package_dict()
    test_server_create_analysis()

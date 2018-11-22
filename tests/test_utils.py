"""Tests for the 'utils' module."""
from src.utils import (
    convert_version_to_proper_semantic as cvs,
    version_info_tuple as vt, select_latest_version as slv,
    get_osio_user_count, create_package_dict, is_quickstart_majority, execute_gremlin_dsl)
import semantic_version as sv
import json
from unittest import mock


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
def test_execute_gremlin_dsl(_mock1):
    """Test error response for gremlin."""
    payload = {'gremlin': ''}
    result = execute_gremlin_dsl(payload)
    assert result is None


if __name__ == '__main__':
    test_semantic_versioning()
    test_version_info_tuple()
    test_select_latest_version()
    test_get_osio_user_count()
    test_is_quickstart_majority()

"""Tests for the sa module."""

import copy
import json
from unittest import mock

from src.v2 import stack_aggregator as sa
from src.v2.models import Package, PackageDetails
from src.v2.normalized_packages import NormalizedPackages

# ref: https://stackoverflow.com/questions/29516339/how-to-mock-calls-to-function-that-receives-mutable-object-as-parameter
# ref: https://docs.python.org/dev/library/unittest.mock-examples.html#coping-with-mutable-arguments
class ModifiedMagicMock(mock.MagicMock):
    def _mock_call(_mock_self, *args, **kwargs):
        return super(ModifiedMagicMock, _mock_self)._mock_call(*copy.deepcopy(args), **copy.deepcopy(kwargs))

def test_create_package_details_without_vuln():
    """Test the function validate_request_data."""
    with open("tests/data/component_sequence.json", "r") as fin:
        payload = json.load(fin)
    pkg, component = sa.create_package_details(payload)
    assert isinstance(pkg, Package)
    assert isinstance(component, PackageDetails)
    expected_keys = (
        "ecosystem",
        "name",
        "version",
        "licenses",
        "public_vulnerabilities",
        "private_vulnerabilities",
        "latest_version",
        "github")
    for key in expected_keys:
        assert key in component.dict(),(
               "Can't found the key '{key}' in result data structure".format(key=key))


@mock.patch('src.v2.stack_aggregator.post_gremlin')
def test_get_recommended_version_empty_gremlin(_mock_gremlin):
    """Test get_recommended_version."""
    _mock_gremlin.return_value = {'result': {'data': []}}
    ver = sa.get_recommended_version('pypi', Package(name='flask', version='0.12'))
    assert ver is None

    _mock_gremlin.return_value = {'result': {'data': ['1.0','1.1','1.2']}}
    ver = sa.get_recommended_version('pypi', Package(name='flask', version='0.12'))
    assert ver is not None
    assert ver == '1.2'

    _mock_gremlin.return_value = {'result': {'data': ['0.12']}}
    ver = sa.get_recommended_version('pypi', Package(name='flask', version='0.12'))
    assert ver is None

    _mock_gremlin.return_value = None
    ver = sa.get_recommended_version('pypi', Package(name='flask', version='0.12'))
    assert ver is None

def test_is_private_vulnerability():
    """Test is_private_vulnerability"""
    assert sa.is_private_vulnerability({'snyk_pvt_vulnerability': [True]})
    assert not sa.is_private_vulnerability({'snyk_pvt_vulnerability': [False]})
    assert not sa.is_private_vulnerability({})

@mock.patch('src.v2.stack_aggregator.post_gremlin', new_callable=ModifiedMagicMock)
def test_get_package_details_with_vulnerabilities(_mock_gremlin):
    # empty
    _mock_gremlin.return_value = None
    packages = NormalizedPackages([], 'pypi')
    result = sa.get_package_details_with_vulnerabilities(packages)
    assert result is not None
    assert isinstance(result, list)
    _mock_gremlin.assert_not_called()

    six = Package(name='six', version='1.2')
    pip = Package(name='pip', version='20.1')
    flask = Package(**{
        'name': 'flask',
        'version': '0.12',
        'dependencies': [
            {
                'name': 'flask-mock',
                'version': '0.0.13'
            }]
    })
    bar = Package(**{
        'name': 'bar',
        'version': '0.12',
        'dependencies': [flask, six, pip]
    })
    packages = NormalizedPackages([flask, bar], 'pypi')

    mock_args_list = []
    def side_effect(*args, **kwargs):
        pass
    _mock_gremlin.return_value = None
    _mock_gremlin.side_effect = side_effect
    with mock.patch('src.v2.stack_aggregator.GREMLIN_QUERY_SIZE', 100):
        _mock_gremlin.reset_mock()
        result = sa.get_package_details_with_vulnerabilities(packages)
        assert _mock_gremlin.call_count == 1
        for call in _mock_gremlin.call_args_list:
            args, kwargs = call
            assert len(args) == 2
            assert args[0].startswith('epv')
            assert isinstance(args[1], dict)
            assert len(args[1]['packages']) == 5

    with mock.patch('src.v2.stack_aggregator.GREMLIN_QUERY_SIZE', 1):
        _mock_gremlin.reset_mock()
        result = sa.get_package_details_with_vulnerabilities(packages)
        assert _mock_gremlin.call_count == 5
        for call in _mock_gremlin.call_args_list:
            args, kwargs = call
            assert len(args) == 2
            assert args[0].startswith('epv')
            assert isinstance(args[1], dict)
            assert len(args[1]['packages']) == 1

    _mock_gremlin.return_value = None
    with mock.patch('src.v2.stack_aggregator.GREMLIN_QUERY_SIZE', 2):
        _mock_gremlin.reset_mock()
        result = sa.get_package_details_with_vulnerabilities(packages)
        assert _mock_gremlin.call_count == 3
        for i, call in enumerate(_mock_gremlin.call_args_list, 1):
            args, kwargs = call
            assert len(args) == 2
            assert args[0].startswith('epv')
            assert isinstance(args[1], dict)
            if i == len(_mock_gremlin.call_args_list):
                assert len(args[1]['packages']) == 1
            else:
                assert len(args[1]['packages']) == 2

    with mock.patch('src.v2.stack_aggregator.GREMLIN_QUERY_SIZE', 3):
        _mock_gremlin.reset_mock()
        result = sa.get_package_details_with_vulnerabilities(packages)
        assert _mock_gremlin.call_count == 2
        for i, call in enumerate(_mock_gremlin.call_args_list, 1):
            args, kwargs = call
            assert len(args) == 2
            assert args[0].startswith('epv')
            assert isinstance(args[1], dict)
            if i == len(_mock_gremlin.call_args_list):
                assert len(args[1]['packages']) == 2
            else:
                assert len(args[1]['packages']) == 3

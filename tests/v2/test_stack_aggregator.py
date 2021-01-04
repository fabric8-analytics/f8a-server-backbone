"""Tests for the sa module."""

import copy
import json
from unittest import mock, TestCase

from src.v2 import stack_aggregator as sa
from src.v2.stack_aggregator import StackAggregator
from src.v2.models import (Package, VulnerabilityFields,
                           StackAggregatorResult,
                           StackAggregatorRequest)
from src.v2.normalized_packages import NormalizedPackages


_DJANGO = Package(name='django', version='1.2.1')
_FLASK = Package(name='flask', version='0.12')
_SIX = Package(name='six', version='3.2.1')
_FOO_UNKNOWN = Package(name='foo_unknown', version='0.0.0')


def _request_body():
    return {
        "registration_status": "REGISTERED",
        "uuid": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "manifest_name": "requirements.txt",
        "manifest_file_path": "/foo/bar",
        "external_request_id": "test_id",
        "ecosystem": "pypi",
        "packages": [
            {
                "name": "flask",
                "version": "0.12",
                "dependencies": [
                    {'name': 'django', 'version': '1.2.1'}
                ]
            }, {
                "name": "django",
                "version": "1.2.1"
            }
         ]
    }


def _go_request_body():
    return {
        "registration_status": "freetier",
        "ecosystem": "golang",
        "external_request_id": "abc",
        "packages": [
            {
                "name": "github.com/gophish/gophish/controllers@github.com/gophish/gophish",
                "version": "v0.0.0-20200827055948-64c3edbc241f",
                "dependencies": [
                    {
                        "name": "github.com/gophish/gophish/"
                                "controllersfdfdf@github.com/gophish/gophish",
                        "version": "0.0.0-20200827055948-64c3edbc241f"
                    }
                ]
            },
            {
                "name": "github.com/gophish/gophish/"
                        "controllerssssssasas@github.com/gophish/gophish",
                "version": "v0.0.0-20200827055948-64c3edbc241f",
                "dependencies": [
                ]
            }
        ],
        "manifest_name": "golist.json",
        "manifest_file_path": "/tmp/bin",
        "show_transitive": True
    }


@mock.patch('src.v2.stack_aggregator.post_gremlin')
@mock.patch('src.v2.stack_aggregator.get_license_analysis_for_stack')
def test_with_2_public_vuln(_mock_license, _mock_gremlin, monkeypatch):
    """Test basic request and response."""
    with open("tests/v2/data/graph_response_2_public_vuln.json", "r") as fin:
        _mock_gremlin.return_value = json.load(fin)

    monkeypatch.setenv('SNYK_PACKAGE_URL_FORMAT', 'https://abc.io/vuln/{ecosystem}:{package}')
    monkeypatch.setenv('SNYK_SIGNIN_URL', 'https://abc.io/login')
    resp = StackAggregator().execute(_request_body(), persist=False)
    _mock_license.assert_called_once()
    _mock_gremlin.assert_called()
    assert resp['aggregation'] == 'success'
    assert resp['result'] is not None
    result = resp['result']
    assert result['external_request_id'] == 'test_id'

    # check _audit
    assert result['_audit'] is not None
    assert result['_audit']['version'] == 'v2'

    # check manifest_name and manifest_file_path
    assert result['manifest_name'] == 'requirements.txt'
    assert result['manifest_file_path'] == '/foo/bar'

    # check analyzed_dependencies
    result = StackAggregatorResult(**result)
    assert result.registration_link == 'https://abc.io/login'
    assert len(result.analyzed_dependencies) == 2
    assert _FLASK in result.analyzed_dependencies
    assert _SIX not in result.analyzed_dependencies

    # check vuln
    django_index = result.analyzed_dependencies.index(_DJANGO)
    assert result.analyzed_dependencies[django_index].url == 'https://abc.io/vuln/pip:django'
    assert len(result.analyzed_dependencies[django_index].public_vulnerabilities) == 2
    assert len(result.analyzed_dependencies[django_index].private_vulnerabilities) == 0
    assert isinstance(result.analyzed_dependencies[django_index].public_vulnerabilities[0],
                      VulnerabilityFields)
    flask_index = result.analyzed_dependencies.index(_FLASK)
    assert len(result.analyzed_dependencies[flask_index].public_vulnerabilities) == 0
    # check transitive vuln
    assert len(result.analyzed_dependencies[flask_index].vulnerable_dependencies) == 1
    assert _DJANGO in result.analyzed_dependencies[flask_index].vulnerable_dependencies
    assert len(result.analyzed_dependencies[flask_index].
               vulnerable_dependencies[0].public_vulnerabilities) == 2


@mock.patch('src.v2.stack_aggregator.post_gremlin')
@mock.patch('src.v2.stack_aggregator.get_license_analysis_for_stack')
def test_with_1_public_1_pvt_vuln(_mock_license, _mock_gremlin):
    """Test with 1 public and 1 private vulnerability."""
    with open("tests/v2/data/graph_response_2_public_vuln.json", "r") as fin:
        resp = json.load(fin)
        # make one vulnerability private
        resp['result']['data'][0]['vuln'][1]['snyk_pvt_vulnerability'] = [True]
        _mock_gremlin.return_value = resp

    resp = StackAggregator().execute(_request_body(), persist=False)
    _mock_license.assert_called_once()
    _mock_gremlin.assert_called()
    assert resp['aggregation'] == 'success'
    assert resp['result'] is not None
    result = resp['result']
    assert result['external_request_id'] == 'test_id'

    # check analyzed_dependencies
    result = StackAggregatorResult(**result)
    assert 'registration_link' in result.dict()
    assert len(result.analyzed_dependencies) == 2
    assert _FLASK in result.analyzed_dependencies
    assert _DJANGO in result.analyzed_dependencies
    assert _SIX not in result.analyzed_dependencies

    # check vuln
    django_index = result.analyzed_dependencies.index(_DJANGO)
    assert len(result.analyzed_dependencies[django_index].public_vulnerabilities) == 1
    assert len(result.analyzed_dependencies[django_index].private_vulnerabilities) == 1
    assert isinstance(result.analyzed_dependencies[django_index].public_vulnerabilities[0],
                      VulnerabilityFields)
    flask_index = result.analyzed_dependencies.index(_FLASK)
    assert len(result.analyzed_dependencies[flask_index].public_vulnerabilities) == 0
    assert len(result.analyzed_dependencies[flask_index].private_vulnerabilities) == 0
    # check transitive vuln
    assert len(result.analyzed_dependencies[flask_index].vulnerable_dependencies) == 1
    assert _DJANGO in result.analyzed_dependencies[flask_index].vulnerable_dependencies
    assert len(result.analyzed_dependencies[flask_index].
               vulnerable_dependencies[0].public_vulnerabilities) == 1


@mock.patch('src.v2.stack_aggregator.post_gremlin')
@mock.patch('src.v2.stack_aggregator.get_license_analysis_for_stack')
def test_with_2_public_vuln_for_registered(_mock_license, _mock_gremlin):
    """Test basic request and response for registered user."""
    with open("tests/v2/data/graph_response_2_public_vuln.json", "r") as fin:
        _mock_gremlin.return_value = json.load(fin)

    payload = _request_body()
    payload['registration_status'] = 'REGISTERED'
    resp = StackAggregator().execute(payload, persist=False)
    _mock_license.assert_called_once()
    _mock_gremlin.assert_called()
    assert resp['aggregation'] == 'success'
    assert resp['result'] is not None
    result = resp['result']
    assert result['external_request_id'] == 'test_id'
    assert result['_audit'] is not None
    assert result['_audit']['version'] == 'v2'

    # check analyzed_dependencies
    result = StackAggregatorResult(**result)
    assert "registration_link" in result.dict()
    assert len(result.analyzed_dependencies) == 2
    assert _FLASK in result.analyzed_dependencies
    assert _DJANGO in result.analyzed_dependencies
    assert _SIX not in result.analyzed_dependencies

    # check vuln
    django_index = result.analyzed_dependencies.index(_DJANGO)
    assert len(result.analyzed_dependencies[django_index].public_vulnerabilities) == 2
    assert isinstance(result.analyzed_dependencies[django_index].public_vulnerabilities[0],
                      VulnerabilityFields)
    flask_index = result.analyzed_dependencies.index(_FLASK)
    assert len(result.analyzed_dependencies[flask_index].public_vulnerabilities) == 0
    # check transitive vuln
    assert len(result.analyzed_dependencies[flask_index].vulnerable_dependencies) == 1
    assert _DJANGO in result.analyzed_dependencies[flask_index].vulnerable_dependencies
    assert len(result.analyzed_dependencies[flask_index].
               vulnerable_dependencies[0].public_vulnerabilities) == 2


@mock.patch('src.v2.stack_aggregator.unknown_package_flow')
@mock.patch('src.v2.stack_aggregator.post_gremlin')
def test_unknown_flow_with_disabled_flag(_mock_gremlin, _mock_unknown, monkeypatch):
    """Test unknown flow."""
    with open("tests/v2/data/graph_response_2_public_vuln.json", "r") as fin:
        _mock_gremlin.return_value = json.load(fin)

    payload = _request_body()
    # add unknown package as direct dependency
    payload['packages'].append(_SIX.dict())

    # Disabled unknown flow check
    monkeypatch.setenv('DISABLE_UNKNOWN_PACKAGE_FLOW', '1')
    StackAggregator().execute(payload, persist=False)
    _mock_unknown.assert_not_called()


@mock.patch('src.v2.stack_aggregator.unknown_package_flow')
@mock.patch('src.v2.stack_aggregator.post_gremlin')
@mock.patch('src.v2.stack_aggregator.get_license_analysis_for_stack')
def test_unknown_flow(_mock_license, _mock_gremlin, _mock_unknown):
    """Test unknown flow."""
    with open("tests/v2/data/graph_response_2_public_vuln.json", "r") as fin:
        _mock_gremlin.return_value = json.load(fin)

    payload = _request_body()
    # add unknown package as direct dependency
    payload['packages'].append(_SIX.dict())
    # add unknown packages as transitive dependency
    payload['packages'][0]['dependencies'].append(_SIX.dict())
    payload['packages'][0]['dependencies'].append(_FOO_UNKNOWN.dict())
    resp = StackAggregator().execute(payload, persist=False)
    _mock_license.assert_called_once()
    _mock_gremlin.assert_called()
    _mock_unknown.assert_called()
    assert resp['aggregation'] == 'success'
    assert resp['result'] is not None
    result = resp['result']
    assert result['external_request_id'] == 'test_id'

    # check analyzed_dependencies
    result = StackAggregatorResult(**result)
    assert len(result.analyzed_dependencies) == 2
    assert len(result.unknown_dependencies) == 1

    assert _SIX in result.unknown_dependencies
    # transitive shouldn't be part of unknown
    assert _FOO_UNKNOWN not in result.unknown_dependencies

    _mock_unknown.reset_mock()
    _mock_unknown.side_effect = Exception('mocked exception')
    resp = StackAggregator().execute(payload, persist=False)
    # unknown ingestion failure is fine.
    assert resp['aggregation'] == 'success'


@mock.patch('src.v2.stack_aggregator.persist_data_in_db')
@mock.patch('src.v2.stack_aggregator.post_gremlin')
@mock.patch('src.v2.stack_aggregator.get_license_analysis_for_stack')
def test_db_store(_mock_license, _mock_gremlin, _mock_store):
    """Test call to RDS."""
    with open("tests/v2/data/graph_response_2_public_vuln.json", "r") as fin:
        _mock_gremlin.return_value = json.load(fin)

    payload = _request_body()
    resp = StackAggregator().execute(payload, persist=True)
    _mock_license.assert_called_once()
    _mock_gremlin.assert_called()
    _mock_store.assert_called_once()
    assert resp['aggregation'] == 'success'
    assert resp['result'] is not None
    result = resp['result']
    assert result['external_request_id'] == 'test_id'


# ref: https://stackoverflow.com/a/29525603/1942688
# ref: https://docs.python.org/dev/library/unittest.mock-examples.html#coping-with-mutable-arguments
class _ModifiedMagicMock(mock.MagicMock):
    def _mock_call(_mock_self, *args, **kwargs):
        return super(_ModifiedMagicMock, _mock_self)._mock_call(*copy.deepcopy(args),
                                                                **copy.deepcopy(kwargs))


def _get_normalized_packages():
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
    return NormalizedPackages([flask, bar], 'pypi')


def _gremlin_batch_test(_mock_gremlin, size: int):
    packages = _get_normalized_packages()
    _mock_gremlin.return_value = None
    with mock.patch('src.v2.stack_aggregator.GREMLIN_QUERY_SIZE', size):
        _mock_gremlin.reset_mock()
        sa.Aggregator(request=StackAggregatorRequest(registration_status="REGISTERED",
                      uuid="3fa85f64-5717-4562-b3fc-2c963f66afa6",
                      external_request_id='test_request_id',
                      ecosystem='pypi', manifest_file_path='/tmp/bin', packages=[_DJANGO]),
                      normalized_packages=packages).get_package_details_from_graph()
        ith = 0
        last = 0
        for i, call in enumerate(_mock_gremlin.call_args_list, start=1):
            args, kwargs = call
            assert len(args) == 2
            assert args[0].startswith('epv')
            assert isinstance(args[1], dict)
            if i == len(_mock_gremlin.call_args_list):
                last = len(args[1]['packages'])
            else:
                ith = len(args[1]['packages'])
        return _mock_gremlin.call_count, ith, last


@mock.patch('src.v2.stack_aggregator.post_gremlin', new_callable=_ModifiedMagicMock)
def test_gremlin_batch_call(_mock_gremlin):
    """Test post_gremlin call according to batch size."""
    # empty
    _mock_gremlin.return_value = None
    packages = NormalizedPackages([], 'pypi')
    result = sa.Aggregator(request=StackAggregatorRequest(registration_status="REGISTERED",
                           uuid="3fa85f64-5717-4562-b3fc-2c963f66afa6",
                           external_request_id='test_request_id',
                           ecosystem='pypi', manifest_file_path='/tmp/bin', packages=[_DJANGO]),
                           normalized_packages=packages).get_package_details_from_graph()
    assert result is not None
    assert isinstance(result, dict)
    _mock_gremlin.assert_not_called()
    assert (1, 0, 5) == _gremlin_batch_test(_mock_gremlin, 100)
    assert (5, 1, 1) == _gremlin_batch_test(_mock_gremlin, 1)
    assert (3, 2, 1) == _gremlin_batch_test(_mock_gremlin, 2)
    assert (2, 3, 2) == _gremlin_batch_test(_mock_gremlin, 3)
    assert (2, 4, 1) == _gremlin_batch_test(_mock_gremlin, 4)
    assert (1, 0, 5) == _gremlin_batch_test(_mock_gremlin, 5)


class TestStackAggregator(TestCase):
    """Test for the Stack Aggregator class."""

    def _mocked_get_data_from_db(*args):
        if args[3] == 'pckg_response':
            with open("tests/v2/data/golang_pkg_node_gremlin_response.json", "r") as fin:
                return json.load(fin)
        elif args[3] == 'module_vulnerabilities':
            with open("tests/v2/data/golang_module_vuls_graph_response.json", "r") as fin:
                return json.load(fin)
        elif args[3] == '_get_pkg_details_with_vuls':
            with open("tests/v2/data/graph_response_2_public_vuln.json", "r") as fin:
                return json.load(fin)

    @mock.patch('src.v2.stack_aggregator.GoAggregator._get_data_from_graph',
                side_effect=_mocked_get_data_from_db, autospec=True)
    @mock.patch('src.v2.stack_aggregator.get_license_analysis_for_stack')
    def test_golang_pseudo_version(self, _mock_lic, _mock_get_data_from_db):
        """Test Golang Pseudo Version functionality."""
        resp = StackAggregator().execute(_go_request_body(), persist=False)
        _mock_get_data_from_db.assert_called()
        _mock_lic.assert_called_once()
        self.assertEqual(resp['aggregation'], 'success')
        self.assertEqual(len(resp['result']['unknown_dependencies']), 1)
        self.assertEqual(len(resp['result']['analyzed_dependencies']), 1)
        self.assertEqual(len(resp['result']['analyzed_dependencies'][0]
                             ['dependencies']), 1)
        self.assertEqual(len(resp['result']['analyzed_dependencies'][0]
                             ['public_vulnerabilities']), 3)

        self.assertEqual(resp['result']['analyzed_dependencies'][0]['url'],
                         'https://snyk.io/vuln/golang:github.com%2Fgophish%2Fgophish%2Fcontrollers')
        self.assertEqual(resp['result']['analyzed_dependencies'][0]
                         ['public_vulnerabilities'][0]['cve_ids'], ['CVE-2020-24711'])
        self.assertEqual(resp['result']['analyzed_dependencies'][0]
                         ['public_vulnerabilities'][0]['title'], 'Denial of Service (DoS)')
        self.assertEqual(resp['result']['analyzed_dependencies'][0]
                         ['public_vulnerabilities'][0]['fixed_in'], ['0.11.0'])
        self.assertEqual(resp['result']['analyzed_dependencies'][0]
                         ['public_vulnerabilities'][0]['id'],
                         'SNYK-GOLANG-GITHUBCOMGOPHISHGOPHISHCONTROLLERS-1023587')

        self.assertEqual(resp['result']['analyzed_dependencies'][0]
                         ['public_vulnerabilities'][1]['cve_ids'], ['CVE-2020-24711'])
        self.assertEqual(resp['result']['analyzed_dependencies'][0]
                         ['public_vulnerabilities'][1]['title'], 'Denial of Service (DoS)')
        self.assertEqual(resp['result']['analyzed_dependencies'][0]
                         ['public_vulnerabilities'][1]['fixed_in'], ['0.11.0'])
        self.assertEqual(resp['result']['analyzed_dependencies'][0]
                         ['public_vulnerabilities'][1]['id'],
                         'SNYK-GOLANG-GITHUBCOMGOPHISHGOPHISHCONTROLLERS-1023585')

        self.assertEqual(resp['result']['analyzed_dependencies'][0]
                         ['public_vulnerabilities'][2]['cve_ids'], ['CVE-2020-24711'])
        self.assertEqual(resp['result']['analyzed_dependencies'][0]
                         ['public_vulnerabilities'][2]['title'], 'Denial of Service (DoS)')
        self.assertEqual(resp['result']['analyzed_dependencies'][0]
                         ['public_vulnerabilities'][2]['fixed_in'], ['0.11.0'])
        self.assertEqual(resp['result']['analyzed_dependencies'][0]
                         ['public_vulnerabilities'][2]['id'],
                         'SNYK-GOLANG-GITHUBCOMGOPHISHGOPHISHCONTROLLERS-1023589')

        list_of_keys = resp['result'].get(
            'analyzed_dependencies')[0]['public_vulnerabilities'][0].keys()
        self.assertIn('exploit', list_of_keys)
        self.assertIn('fixable', list_of_keys)
        self.assertIn('severity', list_of_keys)
        self.assertIn('fixed_in', list_of_keys)
        self.assertEqual(len(resp['result'].get(
            'analyzed_dependencies')[0]['private_vulnerabilities']), 0)
        self.assertIsInstance(resp['result']['registration_link'], str)
        self.assertEqual(resp['result']['ecosystem'], 'golang')

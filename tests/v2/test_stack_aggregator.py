"""Tests for the sa module."""

import json
from unittest import mock
from src.v2 import stack_aggregator as sa
from src.v2.models import Package, PackageDetails

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
        "security",
        "osio_user_count",
        "latest_version",
        "github",
        "code_metrics")
    for key in expected_keys:
        assert (key in component.dict(),
                "Can't found the key '{key}' in result data structure".format(key=key))


@mock.patch('src.v2.stack_aggregator.post_gremlin')
def test_get_recommended_version_empty_gremlin(post_gremlin):
    """Test get_recommended_version."""
    post_gremlin.return_value = {
        'result': {
            'data': []}
    }
    ver = sa.get_recommended_version('pypi', Package(name='flask', version='0.12'))
    assert ver is None


@mock.patch('src.v2.stack_aggregator.post_gremlin')
def test_get_recommended_version_three_versions(post_gremlin):
    """Test get_recommended_version."""
    post_gremlin.return_value = {
        'result': {
            'data': [
                '1.0',
                '1.1',
                '1.2']}
    }
    ver = sa.get_recommended_version('pypi', Package(name='flask', version='0.12'))
    assert ver is not None
    assert ver == '1.2'


@mock.patch('src.v2.stack_aggregator.post_gremlin')
def test_get_recommended_version_same_as_target_pack(post_gremlin):
    """Test get_recommended_version."""
    post_gremlin.return_value = {
        'result': {
            'data': [
                '0.12']}
    }
    ver = sa.get_recommended_version('pypi', Package(name='flask', version='0.12'))
    assert ver is None


@mock.patch('src.v2.stack_aggregator.post_gremlin')
def test_get_recommended_version_no_gremlin_response(post_gremlin):
    """Test get_recommended_version."""
    post_gremlin.return_value = None
    ver = sa.get_recommended_version('pypi', Package(name='flask', version='0.12'))
    assert ver is None

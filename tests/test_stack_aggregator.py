"""Tests for the stack_aggregator module."""

from unittest import TestCase
from unittest.mock import *

from src import stack_aggregator
import json


def test_extract_component_details():
    """Test the function validate_request_data."""
    with open("tests/data/component_sequence.json", "r") as fin:
        payload = json.load(fin)
    results = stack_aggregator.extract_component_details(payload)
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
    for expected_key in expected_keys:
        assert expected_key in results, \
            "Can not found the key '{key}' in result data structure".format(key=expected_key)


def test_aggregate_stack_data():
    """Test the function aggregate_stack_data."""
    pass


def mocked_get_dependency_data_none(resolved, ecosystem):
    """Mock for the function get_dependency_data."""
    return None


@patch('src.stack_aggregator.get_dependency_data', side_effect=mocked_get_dependency_data_none)
def test_extract_user_stack_package_licenses(mocked_function):
    """Test the function extract_user_stack_package_licenses."""
    result = stack_aggregator.extract_user_stack_package_licenses("resolved", "pypi")
    assert result == []


def mocked_get_dependency_data(resolved, ecosystem):
    """Mock for the function get_dependency_data."""
    with open("tests/data/component_sequence.json", "r") as fin:
        payload = json.load(fin)
    return {'result': [{'data': [payload]}]}


@patch('src.stack_aggregator.get_dependency_data', side_effect=mocked_get_dependency_data)
def test_extract_user_stack_package_licenses_2(mocked_function):
    """Test the function extract_user_stack_package_licenses."""
    result = stack_aggregator.extract_user_stack_package_licenses("resolved", "pypi")
    assert result


if __name__ == '__main__':
    test_extract_component_details()
    test_aggregate_stack_data()
    test_extract_user_stack_package_licenses()
    test_extract_user_stack_package_licenses_2()

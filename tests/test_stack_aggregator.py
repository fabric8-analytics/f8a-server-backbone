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


def test_stack_aggregator_constructor():
    """Test the constructor for the StackAggregator class."""
    obj = stack_aggregator.StackAggregator()
    assert obj


def test_extract_conflict_packages():
    """Test the function _extract_conflict_packages."""
    f = open("tests/data/license_component_conflict.json", "r")
    license_payload = json.loads(f.read())

    packages = stack_aggregator._extract_conflict_packages(license_payload)
    assert(len(packages) == 1)


def test_execute():
    """Test the function execute."""
    f = open("tests/data/stack_aggregator_execute_input.json", "r")
    payload = json.loads(f.read())

    s = stack_aggregator.StackAggregator()
    out = s.execute(payload, False, unit_test=True)
    assert(out['stack_aggregator'] == "success")


def test_extract_unknown_packages():
    """Test the function _extract_unknown_packages."""
    f = open("tests/data/license_unknown.json", "r")
    license_payload = json.loads(f.read())

    packages = stack_aggregator._extract_unknown_licenses(license_payload)
    assert(len(packages) == 2)

    f = open("tests/data/license_component_conflict.json", "r")
    license_payload = json.loads(f.read())

    packages = stack_aggregator._extract_unknown_licenses(license_payload)
    assert (len(packages) == 2)


def test_extract_license_outliers():
    """Test the function _extract_license_outliers."""
    f = open("tests/data/license_component_conflict.json", "r")
    license_payload = json.loads(f.read())

    packages = stack_aggregator._extract_license_outliers(license_payload)
    assert(len(packages) == 1)


def test_perform_license_analysis():
    """Test the function perform_license_analysis."""
    out, deps = stack_aggregator.perform_license_analysis([], [], unit_test=True)
    assert (len(deps) == 0)


def test_get_dependency_data():
    """Test the function get_dependency_data."""
    resolved = [{"package": "io.vertx:vertx-core", "version": "3.4.2"}]
    out = stack_aggregator.get_dependency_data(resolved, "maven", unit_test=True)
    assert(len(out['result']) == 1)


def test_aggregate_stack_data():
    """Test the function aggregate_stack_data."""
    out = stack_aggregator.aggregate_stack_data({}, "pom.xml", "maven", [], "/home/JohnDoe", False)
    assert (out['manifest_name'] == "pom.xml")


if __name__ == '__main__':
    test_extract_component_details()
    test_aggregate_stack_data()
    test_stack_aggregator_constructor()
    test_extract_conflict_packages()
    test_extract_unknown_packages()
    test_perform_license_analysis()
    test_get_dependency_data()
    test_aggregate_stack_data()
    test_execute()

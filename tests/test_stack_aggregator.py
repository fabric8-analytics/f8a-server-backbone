"""Tests for the stack_aggregator module."""

from unittest import TestCase
from unittest.mock import *

from src import stack_aggregator
import json


def test_extract_component_details():
    """Test the function validate_request_data."""
    with open("data/component_sequence.json", "r") as fin:
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


if __name__ == '__main__':
    test_extract_component_details()

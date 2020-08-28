"""Test v2 license module."""

import json
from unittest import mock

from src.v2 import license_service as la
from src.v2.models import Package, StackAggregatorPackageData, LicenseAnalysis


def test_get_license_service_request_payload_empty():
    """Test empty args for get_license_service_request_payload."""
    assert la.get_license_service_request_payload({}) == []
    assert la.get_distinct_licenses({}) == set()


def _get_normalized_packages():
    flask = Package(name="flask", version="0.12")
    six = Package(name="six", version="3.1.1")
    flask_details = StackAggregatorPackageData(**flask.dict(),
                                               latest_version="1.1.2",
                                               ecosystem="pypi",
                                               licenses=["ABC"])
    six_details = StackAggregatorPackageData(**six.dict(),
                                             latest_version="3.5.0",
                                             ecosystem="pypi",
                                             licenses=["XYZ", "ABC"])

    return [flask_details, six_details]


def test_get_license_service_request_payload_args():
    """Test 2 args for get_license_service_request_payload."""
    normalized_packages = _get_normalized_packages()
    payload = la.get_license_service_request_payload(normalized_packages)
    assert payload
    assert len(payload) == 2

    distinct_licenses = la.get_distinct_licenses(normalized_packages)
    assert len(distinct_licenses) == 2
    diff = {"ABC", "XYZ"}.difference(distinct_licenses)
    assert len(diff) == 0


@mock.patch("src.v2.license_service.post_http_request",
            side_effect=Exception())
def test_get_license_analysis_for_stack_with_empty_param(_mock_post):
    """Test with empty normalized_packages."""
    result = la.get_license_analysis_for_stack({})
    _mock_post.assert_called_once()
    assert isinstance(result, LicenseAnalysis)
    assert result.conflict_packages is None
    assert result.unknown_licenses is None
    assert result.outlier_packages is None


@mock.patch("src.v2.license_service.post_http_request")
def test_get_license_analysis_for_stack_unknown_licenses(_mock_post):
    """Test for unknown license result."""
    # really unknown
    with open("tests/data/license_unknown.json", "r") as f:
        _mock_post.return_value = json.loads(f.read())

    result = la.get_license_analysis_for_stack(_get_normalized_packages())
    _mock_post.assert_called_once()
    assert isinstance(result, LicenseAnalysis)
    assert result.conflict_packages == []
    assert result.outlier_packages == []
    assert result.unknown_licenses.component_conflict == []
    assert len(result.unknown_licenses.unknown) == 1
    assert result.unknown_licenses.unknown[0].package == "p1"
    assert result.unknown_licenses.unknown[0].license == "REDHAT"


@mock.patch("src.v2.license_service.post_http_request")
def test_get_license_analysis_for_stack_conflict_packages(_mock_post):
    """Test for unknown license result."""
    # conflict_packages
    with open("tests/data/license_component_conflict.json", "r") as f:
        _mock_post.return_value = json.loads(f.read())
    result = la.get_license_analysis_for_stack(_get_normalized_packages())
    _mock_post.assert_called_once()
    assert isinstance(result, LicenseAnalysis)
    assert len(result.conflict_packages) == 1
    assert result.conflict_packages[0].package1 == "package1"
    assert result.conflict_packages[0].package2 == "package2"
    assert result.conflict_packages[0].license1 == "license1"
    assert result.conflict_packages[0].license2 == "license2"
    assert result.unknown_licenses.unknown == []
    assert len(result.unknown_licenses.component_conflict) == 1
    assert result.unknown_licenses.component_conflict[0].package == "p2"
    assert (result.unknown_licenses.component_conflict[0].conflict_licenses[0].
            license1 == "apache 2.0")
    assert (result.unknown_licenses.component_conflict[0].conflict_licenses[0].
            license2 == "gplv2")

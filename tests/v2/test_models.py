"""Tests for the v2 models package."""

import pytest

from pydantic import ValidationError
from src.v2.models import Package, StackAggregatorRequest


def test_pkg_basic():
    """Test basic package properties."""
    pkg = Package(name='flask', version='0.12')

    assert pkg.name == 'flask'
    assert pkg.version == '0.12'


def test_pkg_equvality():
    """Test package equvality."""
    pkg_0 = Package(name='flask', version='0.12')
    pkg_1 = Package(name='flask', version='0.12')

    assert pkg_0 == pkg_1


def test_pkg_non_equvality():
    """Test not equvality."""
    pkg_0 = Package(name='flask', version='0.12')
    pkg_1 = Package(name='flask', version='0.13')

    assert pkg_0 != pkg_1

    pkg_0 = Package(name='flask', version='0.12')
    pkg_1 = Package(name='django', version='0.12')

    assert pkg_0 != pkg_1


def test_pkg_hashing():
    """Test hashing functionality of Package."""
    pkg_0 = Package(name='flask', version='0.12')
    pkg_1 = Package(name='flask', version='0.12')
    pkg_2 = Package(name='flask', version='0.13')
    pkg_3 = Package(name='django', version='0.13')
    pkg_4 = Package(name='flask', version='0.12')
    set_of_pkgs = set([pkg_0, pkg_1, pkg_2, pkg_3, pkg_4])

    assert len(set_of_pkgs) == 3
    assert pkg_0 in set_of_pkgs
    assert pkg_1 in set_of_pkgs
    assert pkg_2 in set_of_pkgs
    assert pkg_3 in set_of_pkgs
    assert pkg_4 in set_of_pkgs
    assert Package(name='bar', version='0.0') not in set_of_pkgs


def test_ecosystem_case_insensitivity():
    """Test ecosystem case insensitivity."""
    request = StackAggregatorRequest(external_request_id='foo',
                                     ecosystem='PyPI',
                                     manifest_name='requests.txt',
                                     manifest_file_path='foo.txt',
                                     packages=[])
    assert request.ecosystem == 'pypi'

    request = StackAggregatorRequest(external_request_id='foo',
                                     ecosystem='pypi',
                                     manifest_name='requests.txt',
                                     manifest_file_path='foo.txt',
                                     packages=[])
    assert request.ecosystem == 'pypi'

    with pytest.raises(ValidationError):
        StackAggregatorRequest(external_request_id='foo',
                               ecosystem='FOO',
                               manifest_name='requests.txt',
                               manifest_file_path='foo.txt',
                               packages=[])

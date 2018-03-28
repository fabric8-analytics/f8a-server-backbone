"""Tests for the 'utils' module."""
from src.utils import (
    convert_version_to_proper_semantic as cvs,
    version_info_tuple as vt)
import semantic_version as sv


def test_semantic_versioning():
    """Check the function cvs()."""
    version = "-1"
    assert cvs(version) == sv.Version("0.0.0")
    version = ""
    assert cvs(version) == sv.Version("0.0.0")
    version = None
    assert cvs(version) == sv.Version("0.0.0")
    version = "1.5.2.RELEASE"
    assert cvs(version) == sv.Version("1.5.2+RELEASE")
    version = "1.5-2.RELEASE"
    assert cvs(version) == sv.Version("1.5.2+RELEASE")
    version = "2"
    assert cvs(version) == sv.Version("2.0.0")
    version = "2.3"
    assert cvs(version) == sv.Version("2.3.0")
    version = "2.0.rc1"
    assert cvs(version) == sv.Version("2.0.0+rc1")


def test_version_info_tuple():
    """Check the function vt()"""
    version_str = "2.0.rc1"
    version_obj = cvs(version_str)
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

if __name__ == '__main__':
    test_semantic_versioning()
    test_version_info_tuple()

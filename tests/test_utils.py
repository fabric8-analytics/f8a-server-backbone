"""Tests for the 'utils' module."""
from src.utils import (
    convert_version_to_proper_semantic as cvs,
    version_info_tuple as vt,
    select_latest_version as slv,
    get_osio_user_count)
import semantic_version as sv


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


def test_get_osio_user_count():
    """Test the function get_osio_user_count."""
    out = get_osio_user_count("maven", "io.vertx:vertx-core", "3.4.2", unit_test=True)
    assert(isinstance(out, int))


if __name__ == '__main__':
    test_semantic_versioning()
    test_version_info_tuple()
    test_select_latest_version()
    test_get_osio_user_count()

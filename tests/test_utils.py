from src.utils import convert_version_to_proper_semantic as cvs


def test_semantic_versionin():
    version = "-1"
    assert cvs(version) == "0.0.0"
    version = ""
    assert cvs(version) == "0.0.0"
    version = None
    assert cvs(version) == "0.0.0"
    version = "1.5.2.RELEASE"
    assert cvs(version) == "1.5.2-RELEASE"
    version = "1.5-2.RELEASE"
    assert cvs(version) == "1.5.2-RELEASE"

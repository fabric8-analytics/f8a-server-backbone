"""Tests for the v2 normalized package module."""

from src.v2.normalized_packages import EPV, NormalizedPackages
from src.v2.models import Package

def test_epv_basic():
    epv = EPV('pypi', 'flask', '0.12')

    assert epv.ecosystem == 'pypi'
    assert epv.package == 'flask'
    assert epv.version == '0.12'

def test_epv_equvality():
    epv_0 = EPV('pypi', 'flask', '0.12')
    epv_1 = EPV('pypi', 'flask', '0.12')

    assert epv_0 == epv_1

def test_epv_non_equvality():
    epv_0 = EPV('pypi', 'flask', '0.12')
    epv_1 = EPV('pypi', 'flask', '0.13')

    assert epv_0 != epv_1

    epv_0 = EPV('pypi', 'flask', '0.12')
    epv_1 = EPV('pypi', 'django', '0.12')

    assert epv_0 != epv_1

    epv_0 = EPV('pypi', 'flask', '0.12')
    epv_1 = EPV('npm', 'flask', '0.13')

    assert epv_0 != epv_1

def test_epv_hashing():
    epv_0 = EPV('pypi', 'flask', '0.12')
    epv_1 = EPV('pypi', 'flask', '0.12')
    epv_2 = EPV('pypi', 'flask', '0.13')
    epv_3 = EPV('pypi', 'django', '0.13')
    epv_4 = EPV('npm', 'flask', '0.12')
    set_of_epvs = set([epv_0, epv_1, epv_2, epv_3, epv_4])

    assert len(set_of_epvs) == 4
    assert epv_0 in set_of_epvs
    assert epv_1 in set_of_epvs
    assert epv_2 in set_of_epvs
    assert epv_3 in set_of_epvs
    assert epv_4 in set_of_epvs
    assert EPV('foo', 'bar', '0.0') not in set_of_epvs

def test_normalized_packages_basic_direct():
    epv = EPV('pypi', 'flask', '0.12')
    foo = Package(**{
        'name': epv.package,
        'version': epv.version
    })
    assert foo != None
    normalized = NormalizedPackages([foo], epv.ecosystem)
    assert normalized != None
    assert normalized.direct_dependencies != None
    assert len(normalized.direct_dependencies) == 1
    assert epv in normalized.direct_dependencies

    # transtives must be empty
    assert len(normalized.transitive_dependencies) == 0

    # all must be 1
    assert normalized.all_dependencies != None
    assert len(normalized.all_dependencies) == 1
    assert epv in normalized.all_dependencies

def test_normalized_packages_basic_transitive():
    flask = EPV('pypi', 'flask', '0.12')
    six = EPV('pypi', 'six', '1.2.3')
    foo = Package(**{
        'name': flask.package,
        'version': flask.version,
        'dependencies': [{
            'name': six.package,
            'version': six.version
            }
         ]
    })
    assert foo != None
    normalized = NormalizedPackages([foo], 'pypi')
    assert normalized != None
    assert normalized.direct_dependencies != None
    assert len(normalized.direct_dependencies) == 1
    assert flask in normalized.direct_dependencies

    # transtive should have an entry
    assert len(normalized.transitive_dependencies) == 1
    assert six in normalized.transitive_dependencies

    # all must be 2
    assert len(normalized.all_dependencies) == 2
    assert flask in normalized.all_dependencies
    assert six in normalized.all_dependencies

def test_normalized_packages_duplicate_transitive():
    flask = EPV('pypi', 'flask', '0.12')
    six = EPV('pypi', 'six', '1.2.3')
    foo = Package(**{
        'name': flask.package,
        'version': flask.version,
        'dependencies': [{
            'name': six.package,
            'version': six.version
            }
         ]
    })
    bar = Package(**{
        'name': flask.package,
        'version': flask.version,
        'dependencies': [{
            'name': six.package,
            'version': six.version
            }
         ]
    })
    assert foo != None
    assert bar != None
    normalized = NormalizedPackages([foo, bar], 'pypi')
    assert normalized != None
    assert normalized.direct_dependencies != None
    assert len(normalized.direct_dependencies) == 1
    assert flask in normalized.direct_dependencies

    # transtive should have an entry
    assert len(normalized.transitive_dependencies) == 1
    assert six in normalized.transitive_dependencies

    # all must be 2
    assert len(normalized.all_dependencies) == 2
    assert flask in normalized.all_dependencies
    assert six in normalized.all_dependencies

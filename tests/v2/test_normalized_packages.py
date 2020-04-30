"""Tests for the v2 normalized package module."""

from src.v2.models import Package
from src.v2.normalized_packages import NormalizedPackages

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

def test_normalized_packages_basic_direct():
    """Test NormalizedPackages with basic dependency."""
    pkg = Package(name='flask', version='0.12')
    foo = Package(**{
        'name': pkg.name,
        'version': pkg.version
    })
    assert foo is not None
    normalized = NormalizedPackages([foo], 'pypi')
    assert normalized is not None
    assert normalized.direct_dependencies is not None
    assert len(normalized.direct_dependencies) == 1
    assert pkg in normalized.direct_dependencies

    # transtives must be empty
    assert len(normalized.transitive_dependencies) == 0

    # all must be 1
    assert normalized.all_dependencies is not None
    assert len(normalized.all_dependencies) == 1
    assert pkg in normalized.all_dependencies

    # dependency_graph
    assert len(normalized.dependency_graph) == 1
    assert pkg in normalized.dependency_graph
    assert len(normalized.dependency_graph[foo]) == 0

def test_normalized_packages_basic_transitive():
    """Test NormalizedPackages with transitives dependency"""
    flask = Package(name='flask', version='0.12')
    six = Package(name='six', version='1.2.3')
    foo = Package(**{
        'name': flask.name,
        'version': flask.version,
        'dependencies': [{
            'name': six.name,
            'version': six.version
            }]
    })
    assert foo is not None
    normalized = NormalizedPackages([foo], 'pypi')
    assert normalized is not None
    assert normalized.direct_dependencies is not None
    assert len(normalized.direct_dependencies) == 1
    assert flask in normalized.direct_dependencies

    # transtive should have an entry
    assert len(normalized.transitive_dependencies) == 1
    assert six in normalized.transitive_dependencies

    # all must be 2
    assert len(normalized.all_dependencies) == 2
    assert flask in normalized.all_dependencies
    assert six in normalized.all_dependencies

    # dependency graph
    assert len(normalized.dependency_graph) == 1
    assert len(normalized.dependency_graph[flask]) == 1
    assert flask in normalized.dependency_graph
    assert six in normalized.dependency_graph[flask]
    assert flask not in normalized.dependency_graph[flask]

def test_normalized_packages_with_duplicates():
    """Test NormalizedPackages with duplicates."""
    flask = Package(name='flask', version='0.12')
    six = Package(name='six', version='1.2')
    pip = Package(name='pip', version='20.1')
    foo = Package(**{
        'name': 'flask',
        'version': '0.12',
        'dependencies': [
            {
                'name': 'six',
                'version': '1.2'
            },
            {
                'name': 'six',
                'version': '1.2'
            },
            {
                'name': 'flask',
                'version': '0.12'
            }]
    })
    bar = Package(**{
        'name': 'bar',
        'version': '0.12',
        'dependencies': [Package(**six.dict()), Package(**pip.dict())]
    })
    normalized = NormalizedPackages([foo, bar], 'pypi')
    assert normalized.ecosystem == 'pypi'
    assert normalized is not None
    assert normalized.direct_dependencies is not None
    assert len(normalized.direct_dependencies) == 2
    assert flask in normalized.direct_dependencies
    assert six not in normalized.direct_dependencies

    # transtive should have an entry
    assert len(normalized.transitive_dependencies) == 3
    assert six in normalized.transitive_dependencies
    assert flask in normalized.transitive_dependencies

    assert len(normalized.all_dependencies) == 4
    assert flask in normalized.all_dependencies
    assert six in normalized.all_dependencies

    # dependency graph test
    assert foo in normalized.dependency_graph
    assert bar in normalized.dependency_graph
    assert flask in normalized.dependency_graph
    assert six not in normalized.dependency_graph
    assert six in normalized.dependency_graph[foo]
    assert foo in normalized.dependency_graph[foo]
    assert flask in normalized.dependency_graph[foo]
    assert pip not in normalized.dependency_graph[foo]
    assert pip in normalized.dependency_graph[bar]
    assert six in normalized.dependency_graph[bar]

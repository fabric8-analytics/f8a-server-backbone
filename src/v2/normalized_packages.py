"""Abstraction for various response models used in V2 implementation"""

from typing import Dict, List, Tuple, Set
from src.v2.models import Package, Ecosystem

class EPV:
    """Abstraction of EPV"""
    def __init__(self, ecosystem: str, package: str, version: str):
        self.ecosystem = ecosystem
        self.package = package
        self.version = version

    def __eq__(self, other: "EPV") -> bool:
        return (self.ecosystem == other.ecosystem and
                self.package == other.package and
                self.version == other.version)

    def __hash__(self) -> str:
        return hash((self.ecosystem, self.package, self.version))

class NormalizedPackages:
    """Duplicate free Package List"""
    def __init__(self, packages: List[Package], ecosystem: Ecosystem):
        self._packages = packages
        self._ecosystem = ecosystem
        self._direct_deps = set()
        self._transitive_deps = set()
        for package in packages:
            self._direct_deps.add(EPV(ecosystem, package.name, package.version))
            for trans_package in package.dependencies:
                self._transitive_deps.add(EPV(ecosystem, trans_package.name, trans_package.version))
        self._all = tuple(self._direct_deps.union(self._transitive_deps))
        self._direct_deps = tuple(self._direct_deps)
        self._transitive_deps = tuple(self._transitive_deps)

    @property
    def direct_dependencies(self) -> Tuple[EPV]:
        """Immutable list of direct dependency EPV"""
        return tuple(self._direct_deps)

    @property
    def transitive_dependencies(self) -> Tuple[EPV]:
        """Immutable list of transitives dependency EPV"""
        return tuple(self._transitive_deps)

    @property
    def all_dependencies(self) -> Tuple[EPV]:
        """Union of all direct and transitives without duplicates"""
        return tuple(self._all)

"""Abstraction for various response models used in V2 implementation."""
import logging
from collections import defaultdict
from typing import List, Tuple, Dict, Set

from src.v2.models import Package, Ecosystem
from f8a_utils.tree_generator import GolangDependencyTreeGenerator
from f8a_utils.gh_utils import GithubUtils

logger = logging.getLogger(__name__)


class NormalizedPackages:
    """Duplicate free Package List."""

    def __init__(self, packages: List[Package], ecosystem: Ecosystem):
        """Create NormalizedPackages by removing all duplicates from packages."""
        self._packages = packages
        self._ecosystem = ecosystem
        self._dependency_graph: Dict[Package, Set[Package]] = defaultdict(set)
        for package in packages:
            # clone without dependencies field
            package_clone = Package(name=package.name, version=package.version)
            self._dependency_graph[package_clone] = self._dependency_graph[package_clone] or set()
            for trans_package in package.dependencies or []:
                trans_clone = Package(name=trans_package.name, version=trans_package.version)
                self._dependency_graph[package].add(trans_clone)
        # unfold set of Package into flat set of Package
        self._transtives: Set[Package] = {d for dep in self._dependency_graph.values() for d in dep}
        self._directs = frozenset(self._dependency_graph.keys())
        self._all = self._directs.union(self._transtives)

    @property
    def direct_dependencies(self) -> Tuple[Package]:
        """Immutable list of direct dependency Package."""
        return tuple(self._directs)

    @property
    def transitive_dependencies(self) -> Tuple[Package]:
        """Immutable list of transitives dependency Package."""
        return tuple(self._transtives)

    @property
    def all_dependencies(self) -> Tuple[Package]:
        """Union of all direct and transitives without duplicates."""
        return tuple(self._all)

    @property
    def dependency_graph(self) -> Dict[Package, Set[Package]]:
        """Return Package with it's transtive without duplicates."""
        return self._dependency_graph

    @property
    def ecosystem(self):
        """Ecosystem value."""
        return self._ecosystem


class GoNormalizedPackages(NormalizedPackages):
    """Duplicate free list of GoNormalised Packages."""

    def __init__(self, packages: List[Package], ecosystem: Ecosystem):
        """Create NormalizedPackages by removing all duplicates from packages."""
        packages, self._modules = clean_and_get_pkgs(packages)
        super().__init__(packages, ecosystem)
        self._version_map = {}
        gh = GithubUtils()
        self.pseudo = set()
        for package in packages:
            # clone without dependencies field
            if gh.is_pseudo_version(package.version):
                self._version_map[package.name] = package.version
                self.pseudo.add(package)
            for trans_package in package.dependencies or []:
                if gh.is_pseudo_version(trans_package.version):
                    self._version_map[trans_package.name] = trans_package.version
                    self.pseudo.add(trans_package)
        # unfold set of Package into flat set of Package
        self._all_except_pseudo = self._all.difference(self.pseudo)

    @property
    def modules(self) -> Tuple[str]:
        """Get Tuple of Package Modules."""
        return tuple(set(self._modules))

    @property
    def version_map(self) -> Dict:
        """Map of Package_name: package_version."""
        return dict(self._version_map)

    @property
    def all_deps_without_pseudo(self) -> Tuple[Package]:
        """Diff of all direct deps and pseudo deps."""
        return tuple(self._all_except_pseudo)


def get_golang_metadata(package) -> Tuple[str, str]:
    """Clean Package Name, Pkg version & get Golang package_module and version_map."""
    package_module = package.name
    package_name = None
    if "@" in package.name:
        package_name, package_module = package.name.split("@")
    if package_name is None:
        package_name = package_module
    return package_name, package_module


def clean_and_get_pkgs(packages) -> Tuple[List[Package], List[str]]:
    """Clean and get golang packages."""
    all_packages: List[Package] = []
    all_modules: List[str] = []
    for direct in packages:
        pkg_name, pkg_mod = get_golang_metadata(direct)
        _, package_version = GolangDependencyTreeGenerator.clean_version(direct.version)
        pkg = Package(name=pkg_name, version=package_version, dependencies=[])
        all_modules.append(pkg_mod)
        for trans_pkg in direct.dependencies or []:
            trans_name, trans_mod = get_golang_metadata(trans_pkg)
            _, trans_version = GolangDependencyTreeGenerator.clean_version(trans_pkg.version)
            trans = Package(name=trans_name, version=trans_version)
            all_modules.append(trans_mod)
            pkg.dependencies.append(trans)
        all_packages.append(pkg)
    return all_packages, all_modules

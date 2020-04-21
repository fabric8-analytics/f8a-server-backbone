"""Abstraction for various response models used in V2 implementation"""

from typing import Dict, List, Tuple

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

class NormalizedPackageDetails:
    """Normalized package information(epv) including transitives"""
    def __init__(self, packages: List[Dict[str, str]]):
        pass

    @property
    def direct(self) -> Tuple[EPV]:
        """Immutable list of direct dependency EPV"""
        pass

    @property
    def transitives(self) -> Tuple[EPV]:
        """Immutable list of transitiv dependency EPV"""
        pass

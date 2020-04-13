"""Abstraction for EPV(Ecosystem, Package, Version)"""

class EPV:
    """Abstraction of EPV"""
    def __init__(self, ecosystem, package, version):
        self.ecosystem = ecosystem
        self.package = package
        self.version = version

    def __eq__(self, other):
        return (self.ecosystem == other.ecosystem and
                self.package == other.package and
                self.version == other.version)

    def __hash__(self):
        return hash((self.ecosystem, self.package, self.version))


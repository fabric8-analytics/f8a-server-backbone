"""Tests for the class DependencyEditor."""

from unittest import TestCase
from unittest import mock

from dependency_editor import DependencyEditor


def test_constructor():
    """Test the constructor of DependencyEditor class."""
    dependencyEditor = DependencyEditor()
    assert dependencyEditor


if __name__ == '__main__':
    test_constructor()

"""Definition of fixtures for static data, sessions etc. used by unit tests."""

import pytest

@pytest.fixture
def client():
    """Provide the client session used by tests."""
    from src.rest_api import app
    with app.test_client() as client:
        yield client

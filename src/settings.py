"""Abstracts settings based on env variables."""


from typing import Dict
from pydantic import BaseSettings, HttpUrl


class AggregatorSettings(BaseSettings):
    """Create Settings from env."""

    snyk_package_url_format: HttpUrl = "https://snyk.io/vuln/{ecosystem}:{package}"
    snyk_signin_url: HttpUrl = "https://snyk.io/login"
    snyk_ecosystem_map: Dict[str, str] = {"pypi": "pip"}
    disable_unknown_package_flow: bool = False


class RecommenderSettings(BaseSettings):
    """Create Recommender Settings from env."""

    chester_service_host: str = "notset"
    pypi_service_host: str = "notset"
    maven_service_host: str = "notset"
    service_port: int = 6006
    unknown_packages_threshold: float = 0.3
    max_companion_packages: int = 5

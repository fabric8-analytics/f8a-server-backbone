"""Abstracts settings based on env variables."""


from typing import Dict
from pydantic import BaseSettings, HttpUrl, AnyHttpUrl


class AggregatorSettings(BaseSettings):
    """Create Settings from env."""

    license_analysis_base_url: AnyHttpUrl = "http://f8a-license-analysis:6162"
    snyk_signin_url: HttpUrl = "https://snyk.io/login"
    snyk_package_url_format: HttpUrl = "https://snyk.io/vuln/{ecosystem}:{package}"
    snyk_ecosystem_map: Dict[str, str] = {"pypi": "pip"}
    disable_unknown_package_flow: bool = False


class RecommenderSettings(BaseSettings):
    """Create Recommender Settings from env."""

    npm_insights_base_url: AnyHttpUrl = "http://f8a-npm-insights:6006"
    pypi_insights_base_url: AnyHttpUrl = "http://f8a-pypi-insights:6006"
    maven_insights_base_url: AnyHttpUrl = "http://f8a-hpf-insights-maven:6006"
    unknown_packages_threshold: float = 0.3
    max_companion_packages: int = 5

class Settings(BaseSettings):
    """General settings."""

    gremlin_url: AnyHttpUrl = "http://bayesian-gremlin-http:8182"

SETTINGS = Settings()
RECOMMENDER_SETTINGS = RecommenderSettings()
AGGREGATOR_SETTINGS = AggregatorSettings()

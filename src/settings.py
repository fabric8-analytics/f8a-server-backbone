"""Abstracts settings based on env variables."""


from typing import Dict
from pydantic import BaseSettings, HttpUrl, AnyHttpUrl, Field


class AggregatorSettings(BaseSettings):
    """Create Settings from env."""

    license_analysis_base_url: AnyHttpUrl = "http://f8a-license-analysis:6162"
    snyk_signin_url: HttpUrl = "https://snyk.io/login"
    snyk_package_url_format: HttpUrl = "https://snyk.io/vuln/{ecosystem}:{package}"
    snyk_ecosystem_map: Dict[str, str] = {"pypi": "pip"}


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


class GunicornSettings(BaseSettings):
    """Gunicorn settings."""

    workers: int = Field(default=2, env="WORKER_COUNT")
    worker_class: str = Field(default="gevent", env="WORKER_CLASS")
    timeout: int = Field(default=120, env="WORKER_TIMEOUT")
    preload: bool = Field(default=True, env="WORKER_PRELOAD")
    worker_connections: int = Field(default=1024, env="WORKER_CONNECTIONS")


SETTINGS = Settings()
RECOMMENDER_SETTINGS = RecommenderSettings()
AGGREGATOR_SETTINGS = AggregatorSettings()
GUNICORN_SETTINGS = GunicornSettings()

"""Abstracts settings based on env variables."""

import os
from typing import Dict
from pydantic import BaseSettings, HttpUrl


# (fixme) Move all settings to read from here.
class Settings(BaseSettings):
    """Create Settings from env."""

    snyk_package_url_format: HttpUrl = 'https://snyk.io/vuln/{ecosystem}:{package}'
    snyk_signin_url: HttpUrl = 'https://snyk.io/login'
    snyk_ecosystem_map: Dict[str, str] = {"pypi": "pip"}

    disable_unknown_package_flow: bool = os.environ.get("DISABLE_UNKNOWN_PACKAGE_FLOW", "") == "1"

"""Gets Alternate and Companion Components recommendation from the recommendation engine.

It also gives a list of packages that are not known to the recommendation engine for further crowd
sourcing.
"""

import datetime
import logging
import time
from typing import List, Dict

from pydantic import BaseModel

from src.utils import get_session_retry, persist_data_in_db, post_gremlin
from src.v2.stack_aggregator import get_github_details, get_snyk_package_link
from src.v2.normalized_packages import NormalizedPackages
from src.settings import RecommenderSettings

from src.v2.models import (
    RecommenderRequest,
    StackRecommendationResult,
    Ecosystem,
    RecommendedPackageData,
)

logger = logging.getLogger(__name__)


class InsightsRequest(BaseModel):
    """InsightsRequest payload model."""

    ecosystem: Ecosystem
    transitive_stack: List[str] = []
    package_list: List[str]
    unknown_packages_ratio_threshold: float = (
        RecommenderSettings().unknown_packages_threshold
    )
    comp_package_count_threshold: int = RecommenderSettings().max_companion_packages


class InsightsCallException(Exception):
    """Exception related to insight service call failures."""


class InsightsWithEmptyPackageException(Exception):
    """Exception for empty request packages."""


def _prepare_insights_url(host: str) -> str:
    assert host
    url = "http://{host}:{port}".format(
        host=host, port=RecommenderSettings().service_port
    )
    endpoint = "{url}/api/v1/companion_recommendation".format(url=url)
    return endpoint


ECOSYSTEM_TO_INSIGHTS_URL = {
    "pypi": _prepare_insights_url(RecommenderSettings().pypi_service_host),
    "npm": _prepare_insights_url(RecommenderSettings().chester_service_host),
    "maven": _prepare_insights_url(RecommenderSettings().maven_service_host),
}


class RecommendationTask:
    """Recommendation task."""

    @staticmethod
    def _call(payload: InsightsRequest):
        """Call the PGM model.

        Calls the PGM model with the normalized manifest information to get
        the relevant packages.
        """
        insights_url = ECOSYSTEM_TO_INSIGHTS_URL.get(payload.ecosystem, None)
        assert insights_url
        try:
            started_at = time.time()
            response = get_session_retry().post(insights_url, json=[payload.dict()])
            response.raise_for_status()
        except Exception as e:
            raise InsightsCallException() from e
        else:
            json_response = response.json()
            logger.info(
                "Recommendation [%s] req.pkgs [%d] elapsed time [%0.2f] sec",
                payload.ecosystem.value,
                len(payload.package_list),
                time.time() - started_at,
            )
            return json_response

    def _get_insights_response(self, normalized_packages: NormalizedPackages):
        package_list = list(
            map(lambda epv: epv.name, normalized_packages.direct_dependencies)
        )
        if not package_list:
            raise InsightsWithEmptyPackageException("Request package list is empty")

        insights_payload = InsightsRequest(
            ecosystem=normalized_packages.ecosystem,
            transitive_stack=list(
                map(lambda epv: epv.name, normalized_packages.transitive_dependencies)
            ),
            package_list=package_list,
        )
        # Call PGM and get the response
        return self._call(insights_payload)

    def _get_recommended_package_details(
        self, insights_response
    ) -> List[RecommendedPackageData]:
        companion_packages = insights_response.get("companion_packages", [])
        package_to_stats_map = dict(
            map(
                lambda x: (x.get("package_name"), x),
                companion_packages,
            )
        )
        packages = list(package_to_stats_map.keys())
        ecosystem = insights_response["ecosystem"]
        query = (
            """g.V().has('ecosystem', ecosystem).has('name', within(name)).valueMap()"""
        )
        started_at = time.time()
        result = post_gremlin(
            query=query, bindings={"ecosystem": ecosystem, "name": packages}
        )
        logger.info(
            "graph req.pkgs [%d] elapsed time [%0.2f] sec",
            len(packages),
            time.time() - started_at,
        )

        def extract_version(data):
            # all versions are not vulnerable if latest_non_cve_version doesn't exist.
            # all versions are vulnerable if latest_non_cve_version is empty.
            recommended_version = data.get(
                "latest_non_cve_version", data.get("latest_version", [""])
            )
            version = recommended_version[0] if len(recommended_version) else ""
            return version

        def has_valid_version(data):
            return extract_version(data) not in ["", "-1"]

        def get_recommendation_statistics(package_name: str) -> Dict[str, str]:
            # below dict has cooccurrence_probability, cooccurrence_count, topic_list
            return package_to_stats_map[package_name]

        def map_to_recommendation_package_data(data):
            name = data.get("name", [""])[0]
            version = extract_version(data)
            return RecommendedPackageData(
                name=name,
                version=version,
                github=get_github_details(data),
                licenses=data.get("declared_licenses", []),
                ecosystem=ecosystem,
                url=get_snyk_package_link(ecosystem, name),
                latest_version=data.get("latest_version", [""])[0],
                # join stats from insight
                **get_recommendation_statistics(name),
            )

        valid_packages = filter(has_valid_version, result["result"]["data"])
        return list(map(map_to_recommendation_package_data, valid_packages))

    def execute(self, arguments=None, persist=True, check_license=False):  # noqa: F841
        """Execute task."""
        started_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        request = RecommenderRequest(**arguments)
        if request.ecosystem != "golang":
            normalized_packages = NormalizedPackages(
                request.packages, request.ecosystem
            )
            insights_response = self._get_insights_response(normalized_packages)
            companion = self._get_recommended_package_details(insights_response[0])
        else:
            companion = []
            logging.warning("Recommendation is not yet implemented for golang")

        result = StackRecommendationResult(
            **arguments,
            companion=companion,
        )

        recommendation = result.dict()
        ended_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        recommendation["_audit"] = {
            "started_at": started_at,
            "ended_at": ended_at,
            "version": "v2",
        }

        external_request_id = request.external_request_id
        if persist:
            persist_data_in_db(
                external_request_id=external_request_id,
                task_result=recommendation,
                worker="recommendation_v2",
                started_at=started_at,
                ended_at=ended_at,
            )
            logger.info(
                "%s Recommendation process completed, result persisted into RDS.",
                external_request_id,
            )
        return {
            "recommendation": "success",
            "external_request_id": external_request_id,
            "result": recommendation,
        }

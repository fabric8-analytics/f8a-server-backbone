"""Gets Alternate and Companion Components recommendation from the recommendation engine.

It also gives a list of packages that are not known to the recommendation engine for further crowd
sourcing.
"""

import datetime
import logging
from typing import List, Dict

from pydantic import BaseModel

from src.utils import get_session_retry, persist_data_in_db, post_gremlin
from src.v2.stack_aggregator import get_github_details, get_snyk_package_link
from src.v2.normalized_packages import NormalizedPackages
from src.settings import Settings

from src.v2.models import (
    RecommenderRequest,
    StackRecommendationResult,
    PackageDetails,
    Ecosystem,
    RecommendedPackageData,
    Package,
)

logger = logging.getLogger(__name__)


class InsightsRequest(BaseModel):
    """InsightsRequest payload model."""

    ecosystem: Ecosystem
    transitive_stack: List[str] = []
    package_list: List[str]
    unknown_packages_ratio_threshold: float = Settings().unknown_packages_threshold
    comp_package_count_threshold: int = Settings().max_companion_packages


class InsightsCallException(Exception):
    """Exception related to insight service call failures."""


class InsightsWithEmptyPackageException(Exception):
    """Exception for empty request packages."""


def _prepare_insights_url(host: str) -> str:
    assert host
    url = "http://{host}:{port}".format(host=host, port=Settings().service_port)
    endpoint = "{url}/api/v1/companion_recommendation".format(url=url)
    return endpoint


ECOSYSTEM_TO_SERVICE_HOST = {
    "pypi": _prepare_insights_url(Settings().pypi_service_host),
    "npm": _prepare_insights_url(Settings().chester_service_host),
    "maven": _prepare_insights_url(Settings().maven_service_host),
}


class RecommendationTask:
    """Recommendation task."""

    @staticmethod
    def _call(payload: InsightsRequest):
        """Call the PGM model.

        Calls the PGM model with the normalized manifest information to get
        the relevant packages.
        """
        insights_url = ECOSYSTEM_TO_SERVICE_HOST.get(payload.ecosystem, None)
        assert insights_url
        try:
            response = get_session_retry().post(insights_url, json=[payload.dict()])
            response.raise_for_status()
        except Exception as e:
            raise InsightsCallException() from e
        else:
            json_response = response.json()
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

    def _get_package_details(self, insights_response) -> Dict[str, PackageDetails]:
        packages = list(
            map(
                lambda x: x.get("package_name"),
                insights_response.get("companion_packages", []),
            )
        )
        ecosystem = insights_response["ecosystem"]
        query = (
            """g.V().has('ecosystem', ecosystem).has('name', within(name)).valueMap()"""
        )
        result = post_gremlin(
            query=query, bindings={"ecosystem": ecosystem, "name": packages}
        )

        def map_package(data):
            name = data.get("name", [""])[0]
            version = data.get("latest_non_cve_version", [""])[0]
            pkg = Package(name=name, version=version)
            return name, PackageDetails(
                **pkg.dict(),
                github=get_github_details(data),
                licenses=data.get("declared_licenses", []),
                ecosystem=ecosystem,
                url=get_snyk_package_link(ecosystem, name),
                latest_version=data.get("latest_version", [""])[0]
            )

        return dict(map(map_package, result["result"]["data"]))

    def _get_recommended_package_details(
        self, insights_response
    ) -> List[RecommendedPackageData]:
        package_details = self._get_package_details(insights_response)

        def map_response(r):
            package_detail = package_details[r["package_name"]]
            return RecommendedPackageData(
                **package_detail.dict(),
                cooccurrence_probability=r.get("cooccurrence_probability", 0),
                cooccurrence_count=r.get("cooccurrence_count", 0),
                topic_list=r.get("topic_list", [])
            )

        # remove recommended packages which are not in database.
        recommended_packages = filter(
            lambda r: package_details.get(r["package_name"]),
            insights_response["companion_packages"],
        )
        # map to RecommendedPackageData
        recommended_packages = map(map_response, recommended_packages)
        # remove packages which has empty version string.
        recommended_packages = filter(
            lambda pkg: pkg.version != "", recommended_packages
        )
        return list(recommended_packages)

    def execute(self, arguments=None, persist=True, check_license=False): # noqa: F841
        """Execute task."""
        started_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        request = RecommenderRequest(**arguments)
        if request.ecosystem == "golang":
            logging.warning("Recommendation is yet to be implemented for golang")
            return {}

        external_request_id = request.external_request_id

        normalized_packages = NormalizedPackages(request.packages, request.ecosystem)
        insights_response = self._get_insights_response(normalized_packages)

        result = StackRecommendationResult(
            **arguments,
            companion=self.get_recommended_package_details(insights_response[0]),
            usage_outliers=[]
        )

        recommendation = result.dict()
        ended_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        recommendation["_audit"] = {
            "started_at": started_at,
            "ended_at": ended_at,
            "version": "v2",
        }

        if persist:
            persist_data_in_db(
                external_request_id=request.external_request_id,
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

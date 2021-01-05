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
    ecosystem: Ecosystem
    transitive_stack: List[str] = []
    package_list: List[str]
    unknown_packages_ratio_threshold: float = Settings().unknown_packages_threshold
    comp_package_count_threshold: int = Settings().max_companion_packages


class InsightsCallException(Exception):
    """Exception related to insight service call failures."""


class InsightsWithEmptyPackageException(Exception):
    """Exception for empty request packages."""


ECOSYSTEM_TO_SERVICE_HOST = {
    "pypi": Settings().pypi_service_host,
    "npm": Settings().chester_service_host,
    "maven": Settings().maven_service_host,
}


class RecommendationTask:
    """Recommendation task."""

    @staticmethod
    def get_url(payload: InsightsRequest):
        """Get the insights url based on the ecosystem."""

        host = ECOSYSTEM_TO_SERVICE_HOST.get(payload.ecosystem)
        assert host
        url = "http://{host}:{port}".format(host=host, port=Settings().service_port)
        endpoint = "{url}/api/v1/companion_recommendation".format(url=url)
        return endpoint

    @staticmethod
    def call(payload: InsightsRequest):
        """Call the PGM model.

        Calls the PGM model with the normalized manifest information to get
        the relevant packages.
        """
        insights_url = RecommendationTask.get_url(payload)
        try:
            response = get_session_retry().post(insights_url, json=[payload.dict()])
            response.raise_for_status()
        except Exception as e:
            raise InsightsCallException() from e
        else:
            json_response = response.json()
            return json_response

    def get_insights_response(self, normalized_packages: NormalizedPackages):
        package_list = [epv.name for epv in normalized_packages.direct_dependencies]
        if not package_list:
            raise InsightsWithEmptyPackageException("Request package list is empty")

        insights_payload = InsightsRequest(
            ecosystem=normalized_packages.ecosystem,
            transitive_stack=[
                epv.name for epv in normalized_packages.transitive_dependencies
            ],
            package_list=package_list,
        )
        # Call PGM and get the response
        return self.call(insights_payload)

    def get_package_details(self, insights_response) -> Dict[str, PackageDetails]:
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

    def _empty_package(self, name: str, ecosystem: str) -> PackageDetails:
        return PackageDetails(
            name=name, version="n/a", ecosystem=ecosystem, latest_version="n/a"
        )

    def get_recommended_package_details(
        self, insights_response
    ) -> List[RecommendedPackageData]:
        package_details = self.get_package_details(insights_response)
        ecosystem = insights_response["ecosystem"]

        def map_response(r):
            package_detail = package_details.get(
                r["package_name"], self._empty_package(r["package_name"], ecosystem)
            )
            return RecommendedPackageData(
                **package_detail.dict(),
                cooccurrence_probability=r.get("cooccurrence_probability", 0),
                cooccurrence_count=r.get("cooccurrence_count", 0),
                topic_list=r.get("topic_list", [])
            )

        return list(map(map_response, insights_response["companion_packages"]))

    def execute(self, arguments=None, persist=True, check_license=False):
        """Execute task."""
        started_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        request = RecommenderRequest(**arguments)
        if request.ecosystem == "golang":
            logging.warning("Recommendation is yet to be implemented for golang")
            return {}

        external_request_id = request.external_request_id

        normalized_packages = NormalizedPackages(request.packages, request.ecosystem)
        insights_response = self.get_insights_response(normalized_packages)

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

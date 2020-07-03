"""An implementation of stack aggregator.

Gathers component data from the graph database and aggregate the data to be presented
by stack-analyses endpoint
"""

import datetime
import inspect
import time
from flask import current_app


from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Union, Set
from src.settings import Settings
from src.utils import (select_latest_version, server_create_analysis,
                       persist_data_in_db, post_gremlin, GREMLIN_QUERY_SIZE,
                       format_date)
from src.v2.models import (StackAggregatorRequest, GitHubDetails, PackageDetails,
                           BasicVulnerabilityFields, PremiumVulnerabilityFields,
                           PackageDetailsForFreeTier,
                           PackageDetailsForRegisteredUser,
                           Package, Audit, Ecosystem,
                           StackAggregatorResultForFreeTier,
                           StackAggregatorResultForRegisteredUser)
from src.v2.normalized_packages import NormalizedPackages
from src.v2.license_service import (get_license_analysis_for_stack,
                                    get_license_service_request_payload)


_TRUE = ['true', True, 1, '1']


def _is_private_vulnerability(vulnerability_node):
    """Check whether the given node contains private vulnerability."""
    return vulnerability_node.get('snyk_pvt_vulnerability', [False])[0]


def _get_vuln_for_free_tier(vuln_node: Dict[str, str]):
    """Get fields associated with free tier users."""
    return {
        'id': vuln_node.get('snyk_vuln_id')[0],
        'cvss': vuln_node.get('cvss_scores', [''])[0],
        'cve_ids': vuln_node.get('snyk_cve_ids', []),
        'cvss_v3': vuln_node.get('snyk_cvss_v3')[0],
        'cwes': vuln_node.get('snyk_cwes'),
        'severity': vuln_node.get('severity')[0],
        'title': vuln_node.get('title')[0],
        'url': vuln_node.get('snyk_url')[0],
    }


def _get_vuln_for_registered_user(vuln_node: Dict[str, str]):
    """Get fields associated with registered users."""
    info_free_tier = _get_vuln_for_free_tier(vuln_node)
    info_for_registered_user = {
        'description': vuln_node.get('description')[0],
        'exploit': vuln_node.get('exploit')[0],
        'malicious': vuln_node.get('malicious', [''])[0] in _TRUE,
        'patch_exists': vuln_node.get('patch_exists', [''])[0] in _TRUE,
        'fixable': vuln_node.get('fixable', [''])[0] in _TRUE,
        'fixed_in': vuln_node.get('fixed_in', []),
    }
    return {**info_free_tier, **info_for_registered_user}


def _get_github_details(package_node) -> GitHubDetails:
    """Get fields associated with Github statistics of a package node."""
    date = format_date(package_node.get("gh_refreshed_on", ["N/A"])[0])
    github_details = {
        "dependent_projects":
            package_node.get("libio_dependents_projects", [-1])[0],
        "dependent_repos": package_node.get("libio_dependents_repos", [-1])[0],
        "total_releases": package_node.get("libio_total_releases", [-1])[0],
        "latest_release_duration":
            str(datetime.datetime.fromtimestamp(package_node.get(
                "libio_latest_release", [1496302486.0])[0])),
        "first_release_date": "Apr 16, 2010",
        "issues": {
            "month": {
                "opened": package_node.get("gh_issues_last_month_opened", [-1])[0],
                "closed": package_node.get("gh_issues_last_month_closed", [-1])[0]
            }, "year": {
                "opened": package_node.get("gh_issues_last_year_opened", [-1])[0],
                "closed": package_node.get("gh_issues_last_year_closed", [-1])[0]
            }},
        "pull_requests": {
            "month": {
                "opened": package_node.get("gh_prs_last_month_opened", [-1])[0],
                "closed": package_node.get("gh_prs_last_month_closed", [-1])[0]
            }, "year": {
                "opened": package_node.get("gh_prs_last_year_opened", [-1])[0],
                "closed": package_node.get("gh_prs_last_year_closed", [-1])[0]
            }},
        "stargazers_count": package_node.get("gh_stargazers", [-1])[0],
        "forks_count": package_node.get("gh_forks", [-1])[0],
        "refreshed_on": date,
        "open_issues_count": package_node.get("gh_open_issues_count", [-1])[0],
        "contributors": package_node.get("gh_contributors_count", [-1])[0],
        "size": "N/A"
    }
    used_by = package_node.get("libio_usedby", [])
    used_by_list = []
    for epvs in used_by:
        slc = epvs.split(':')
        used_by_dict = {
            'name': slc[0],
            'stars': int(slc[1])
        }
        used_by_list.append(used_by_dict)
    github_details['used_by'] = used_by_list
    return GitHubDetails(**github_details)


def _get_pkg_from_graph_version_node(version_node) -> Tuple[Ecosystem, Package]:
    """Create Package instance from version_node."""
    name = version_node.get("pname", [""])[0]
    version = version_node.get("version", [""])[0]
    ecosystem = version_node.get("pecosystem", [""])[0]
    return ecosystem, Package(name=name, version=version)


# (fixme): This should be moved to v2/recommender
def extract_user_stack_package_licenses(packages: NormalizedPackages):
    """Extract user stack package licenses."""
    normalized_package_details = (Freetier(normalized_packages=packages).
                                  get_package_details_from_graph(packages))
    return get_license_service_request_payload(normalized_package_details)


def _get_packages_in_batch(dependencies: Tuple[Package], size: int) -> Tuple[Package]:
    """Take Package Tuple and slices it according to size."""
    for i in range(0, len(dependencies), size):
        yield dependencies[i:i + size]


def _has_vulnerability(pkg: PackageDetails) -> bool:
    return pkg and (pkg.public_vulnerabilities or pkg.private_vulnerabilities)


# (fixme) link to snyk package should be identified during ingestion.
def _get_snyk_package_link(ecosystem, package):
    ecosystem = Settings().snyk_ecosystem_map.get(ecosystem, ecosystem)
    return Settings().snyk_package_url_format.format(ecosystem=ecosystem,
                                                     package=package)


class Aggregator(ABC):
    """Base class which contains common functionality related to aggregation."""

    def __init__(self,
                 request: StackAggregatorRequest = None,
                 normalized_packages: NormalizedPackages = None):
        """Initialize common fields."""
        self._request = request
        self._normalized_packages = normalized_packages
        self._normalized_package_details = None
        self._result = None

    def get_package_details_from_graph(self) -> Dict[Package, PackageDetails]:
        """Get dependency data from graph."""
        graph_response = self._get_package_details_with_vulnerabilities()
        package_details: List[Tuple[Package, PackageDetails]] = []
        for pkg in graph_response:
            package_details.append(self._get_package_details(pkg))
        # covert list of (pkg, package_details) into map
        return dict(package_details)

    def _get_vulnerabilities(self, vulnerability_nodes):
        """Get list of vulnerabilities associated with a package."""
        public_vulns = []
        private_vulns = []
        for vuln in vulnerability_nodes:
            if _is_private_vulnerability(vuln):
                private_vulns.append(self.create_vulnerability(vuln))
            else:
                public_vulns.append(self.create_vulnerability(vuln))
        return public_vulns, private_vulns

    def _get_package_details(self, component):
        """Extract package details from given graph response."""
        pkg_node = component.get("package", {})
        version_node = component.get("version", {})
        ecosystem, pkg = _get_pkg_from_graph_version_node(version_node)
        github_details = _get_github_details(pkg_node)
        public_vulns, private_vulns = self._get_vulnerabilities(component.get("vuln", {}))
        recommended_latest_version = pkg_node.get("latest_non_cve_version", [""])[0]
        licenses = version_node.get("declared_licenses", [])

        latest_version = select_latest_version(
            pkg.version,
            pkg_node.get("libio_latest_version", [""])[0],
            pkg_node.get("latest_version", [""])[0],
            pkg.name
        )
        return pkg, self.create_package_details(**pkg.dict(), ecosystem=ecosystem,
                                                latest_version=latest_version,
                                                github=github_details, licenses=licenses,
                                                # (fixme) this is incorrect
                                                url=_get_snyk_package_link(ecosystem,
                                                                           pkg.name),
                                                private_vulnerabilities=private_vulns,
                                                public_vulnerabilities=public_vulns,
                                                recommended_version=recommended_latest_version)

    def _get_package_details_with_vulnerabilities(self) -> List[Dict[str, object]]:
        """Get package data from graph along with vulnerability."""
        eri = self._request.external_request_id if self._request is not None else 'UNKNOWN'
        time_start = time.time()
        pkgs_with_vuln = {
            "result": {
                "data": []
            }
        }
        query = """
                epv = [];
                packages.each {
                    g.V().has('pecosystem', ecosystem).
                    has('pname', it.name).
                    has('version', it.version).as('version', 'vuln').
                    select('version').in('has_version').dedup().as('package').
                    select('package', 'version', 'vuln').
                    by(valueMap()).
                    by(valueMap()).
                    by(out('has_snyk_cve').valueMap().fold()).
                    fill(epv);
                }
                epv;
                """
        # get rid of leading white spaces
        query = inspect.cleandoc(query)
        bindings = {
            'ecosystem': self._normalized_packages.ecosystem,
            'packages': []
        }
        # call gremlin in batches of GREMLIN_QUERY_SIZE
        for pkgs in _get_packages_in_batch(self._normalized_packages.all_dependencies,
                                           GREMLIN_QUERY_SIZE):
            # convert Tuple[Package] into List[{name:.., version:..}]
            bindings['packages'] = [pkg.dict(exclude={'dependencies'}) for pkg in pkgs]

            started_at = time.time()

            result = post_gremlin(query, bindings)

            elapsed_secs = time.time() - started_at
            current_app.logger.info(
                '%s took %0.2f secs for post_gremlin() batch request',
                eri, elapsed_secs)
            if result:
                pkgs_with_vuln['result']['data'] += result['result']['data']

        elapsed_secs = time.time() - time_start
        current_app.logger.info('%s took %0.2f secs for get_package_details_with_'
                                'vulnerabilities() for total_results %d', eri,
                                elapsed_secs, len(pkgs_with_vuln['result']['data']))
        return pkgs_with_vuln['result']['data']

    def _get_denormalized_package_details(self) -> List[PackageDetails]:
        """Pack PackageDetails according to it's dependency graph structure."""
        package_details = []
        for package, transitives in self._normalized_packages.dependency_graph.items():
            package_detail = self._normalized_package_details.get(package)
            if package_detail:
                package_detail = package_detail.copy()
            else:
                continue  # pragma: no cover
            transitive_details = []
            for transitive in transitives:
                transitive_detail = self._normalized_package_details.get(transitive)
                if _has_vulnerability(transitive_detail):
                    transitive_detail = transitive_detail.copy()
                else:
                    continue  # pragma: no cover
                transitive_details.append(transitive_detail)
            package_detail.dependencies = list(transitives)
            package_detail.vulnerable_dependencies = transitive_details
            package_details.append(package_detail)
        return package_details

    def get_all_unknown_packages(self) -> Set[Package]:
        """Get list of all unknowns from the normalized_package_details."""
        all_dependencies = set(self._normalized_packages.all_dependencies)
        analyzed_dependencies = set(self._normalized_package_details.keys())
        return all_dependencies.difference(analyzed_dependencies)

    def _get_direct_unknown_packages(self) -> Set[Package]:
        """Get list of direct unknowns from the normalized_package_details."""
        all_dependencies = set(self._normalized_packages.direct_dependencies)
        analyzed_dependencies = set(self._normalized_package_details.keys())
        return all_dependencies.difference(analyzed_dependencies)

    @abstractmethod
    def create_vulnerability(self,
                             vuln_node: Dict[str, str]) -> Union[BasicVulnerabilityFields,
                                                                 PremiumVulnerabilityFields]:
        """Create Vulnerability object according to the request type."""
        pass  # pragma: no cover

    @abstractmethod
    def create_package_details(self,
                               **kwargs) -> Union[PackageDetailsForFreeTier,
                                                  PackageDetailsForRegisteredUser]:
        """Create PackageDetails object according to the request type."""
        pass  # pragma: no cover

    @abstractmethod
    def create_result(self,
                      **kwargs) -> Union[StackAggregatorResultForFreeTier,
                                         StackAggregatorResultForRegisteredUser]:
        """Create aggregation result according to the request type."""
        pass  # pragma: no cover

    def fetch_details(self):
        """Fetch package & vulnerability info from graph."""
        self._normalized_package_details = self.get_package_details_from_graph()

    def get_result(self) -> Union[StackAggregatorResultForFreeTier,
                                  StackAggregatorResultForRegisteredUser]:
        """Aggregate stack data."""
        # denormalize package details according to request.dependencies relations
        package_details = self._get_denormalized_package_details()
        unknown_dependencies = self._get_direct_unknown_packages()
        started_at = time.time()

        license_analysis = get_license_analysis_for_stack(package_details)

        eri = self._request.external_request_id if self._request is not None else 'UNKNOWN'
        elapsed_secs = time.time() - started_at
        current_app.logger.info(
            '%s took %0.2f secs for get_license_analysis_for_stack()', eri, elapsed_secs)
        return self.create_result(**self._request.dict(exclude={'packages'}),
                                  analyzed_dependencies=package_details,
                                  unknown_dependencies=unknown_dependencies,
                                  license_analysis=license_analysis)


class Freetier(Aggregator):
    """Create Freetier response."""

    def __init__(self, request: StackAggregatorRequest = None,
                 normalized_packages: NormalizedPackages = None):
        """Create Freetier instance."""
        super().__init__(request, normalized_packages)

    def create_package_details(self, **kwargs) -> PackageDetailsForFreeTier:
        """Get PackageDetailsForFreeTier."""
        return PackageDetailsForFreeTier(**kwargs)

    def create_vulnerability(self, vuln_node: Dict[str, str]) -> BasicVulnerabilityFields:
        """Get fields associated with free tier users."""
        return BasicVulnerabilityFields(**_get_vuln_for_free_tier(vuln_node))

    def create_result(self, **kwargs) -> StackAggregatorResultForFreeTier:
        """Get StackAggregatorResultForFreeTier."""
        return StackAggregatorResultForFreeTier(**kwargs,
                                                registration_link=Settings().snyk_signin_url)


class Registered(Aggregator):
    """Create registered user response."""

    def __init__(self, request: StackAggregatorRequest = None,
                 normalized_packages: NormalizedPackages = None):
        """Create Registered instance."""
        super().__init__(request, normalized_packages)

    def create_package_details(self, **kwargs) -> PackageDetailsForRegisteredUser:
        """Create PackageDetailsForRegisteredUser."""
        return PackageDetailsForRegisteredUser(**kwargs)

    def create_vulnerability(self, vuln_node: Dict[str, str]) -> PremiumVulnerabilityFields:
        """Get fields associated with registered users."""
        return PremiumVulnerabilityFields(**_get_vuln_for_registered_user(vuln_node))

    def create_result(self, **kwargs) -> StackAggregatorResultForRegisteredUser:
        """Get StackAggregatorResultForRegisteredUser."""
        return StackAggregatorResultForRegisteredUser(**kwargs)


def initiate_unknown_package_ingestion(external_request_id, aggregator: Aggregator):
    """Ingestion of Unknown dependencies."""
    if Settings().disable_unknown_package_flow:
        current_app.logger.warning(
            '%s Skipping unknown flow %s',
            external_request_id, aggregator.get_all_unknown_packages())
        return

    ecosystem = aggregator._normalized_packages.ecosystem
    try:
        for dep in aggregator.get_all_unknown_packages():
            server_create_analysis(ecosystem, dep.name, dep.version, api_flow=True,
                                   force=False, force_graph_sync=True)
    except Exception as e:  # pylint:disable=W0703,C0103
        current_app.logger.error(
            '%s Ingestion failed for {%s, %s, %s}',
            external_request_id, ecosystem, dep.name, dep.version)
        current_app.logger.error(e)


class StackAggregator:
    """Aggregate stack data from components."""

    @staticmethod
    def process_request(request: Dict) -> Aggregator:
        """Task code."""
        request = StackAggregatorRequest(**request)
        normalized_packages = NormalizedPackages(request.packages,
                                                 request.ecosystem)
        if request.registration_status == 'registered':
            aggregator = Registered(request, normalized_packages)
        else:
            aggregator = Freetier(request, normalized_packages)

        aggregator.fetch_details()
        return aggregator

    @staticmethod
    def execute(request: Dict, persist=True):
        """Task code."""
        # (fixme): Use timestamp instead of str representation.
        execute_started_at = time.time()
        started_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        aggregator = StackAggregator.process_request(request)
        output = aggregator.get_result()
        output_dict = output.dict()
        ended_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        # (fixme): Remove _ to make it as part of pydantic model.
        output_dict["_audit"] = Audit(started_at=started_at, ended_at=ended_at,
                                      version="v2").dict()
        if persist:
            persist_data_in_db(external_request_id=output.external_request_id,
                               task_result=output_dict, worker='stack_aggregator_v2',
                               started_at=started_at, ended_at=ended_at)
            current_app.logger.info(
                '%s Aggregation process completed, result persisted into RDS',
                output.external_request_id)

        initiate_unknown_package_ingestion(output.external_request_id, aggregator)
        # result attribute is added to keep a compatibility with v1
        # otherwise metric accumulator related handling has to be
        # customized for v2.

        # compute the elapsed time
        elapsed_secs = time.time() - execute_started_at
        current_app.logger.info(
            '%s took %0.2f secs for StackAggregator.execute()',
            output.external_request_id, elapsed_secs)

        return {'aggregation': 'success',
                'external_request_id': output.external_request_id,
                'result': output_dict}

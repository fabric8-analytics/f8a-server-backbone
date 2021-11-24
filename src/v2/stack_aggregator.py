"""An implementation of stack aggregator.

Gathers component data from the graph database and aggregate the data to be presented
by stack-analyses endpoint
"""

import datetime
import inspect
import time
import json
import logging
from collections import defaultdict
from urllib.parse import quote

from typing import Dict, List, Tuple, Set
from f8a_utils.gh_utils import GithubUtils
from f8a_utils.ingestion_utils import unknown_package_flow

from src.settings import AGGREGATOR_SETTINGS
from src.utils import (persist_data_in_db, post_gremlin, GREMLIN_QUERY_SIZE,
                       format_date)
from src.v2.models import (StackAggregatorRequest, GitHubDetails, PackageDetails,
                           VulnerabilityFields,
                           PackageDataWithVulnerabilities,
                           Package, Audit, Ecosystem,
                           StackAggregatorResult)
from src.v2.normalized_packages import NormalizedPackages, GoNormalizedPackages
from src.v2.license_service import (get_license_analysis_for_stack,
                                    get_license_service_request_payload)
from f8a_utils import ingestion_utils

logger = logging.getLogger(__name__)
_TRUE = ['true', True, 1, '1']


def _is_private_vulnerability(vulnerability_node):
    """Check whether the given node contains private vulnerability."""
    return vulnerability_node.get('snyk_pvt_vulnerability', [False])[0]


def _get_vulnerability_fields(vuln_node: Dict[str, str]):
    """Get fields associated with vulnerability."""
    return {
        'id': vuln_node.get('snyk_vuln_id')[0],
        'cvss': vuln_node.get('cvss_scores', [''])[0],
        'cve_ids': vuln_node.get('snyk_cve_ids', []),
        'cvss_v3': vuln_node.get('snyk_cvss_v3')[0],
        'cwes': vuln_node.get('snyk_cwes'),
        'severity': vuln_node.get('severity')[0],
        'title': vuln_node.get('title')[0],
        'url': vuln_node.get('snyk_url')[0],
        'description': vuln_node.get('description')[0],
        'exploit': vuln_node.get('exploit')[0],
        'malicious': vuln_node.get('malicious', [''])[0] in _TRUE,
        'patch_exists': vuln_node.get('patch_exists', [''])[0] in _TRUE,
        'fixable': vuln_node.get('fixable', [''])[0] in _TRUE,
        'fixed_in': vuln_node.get('fixed_in', []),
    }


def get_github_details(package_node) -> GitHubDetails:
    """Get fields associated with Github statistics of a package node."""
    date = format_date(package_node.get("gh_refreshed_on", ["N/A"])[0])
    github_details = {
        "dependent_projects":
            package_node.get("libio_dependents_projects", [-1])[0],
        "dependent_repos": package_node.get("libio_dependents_repos", [-1])[0],
        "total_releases": package_node.get("libio_total_releases", [-1])[0],
        "latest_release_duration":
            str(datetime.datetime.utcfromtimestamp(package_node.get(
                "libio_latest_release", [1496302486.0])[0])),
        "watchers": package_node.get("gh_subscribers_count", [-1])[0],
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
    normalized_package_details = (Aggregator(normalized_packages=packages).
                                  get_package_details_from_graph(packages))
    return get_license_service_request_payload(normalized_package_details)


def _get_vulnerabilities(vulnerability_nodes):
    """Get list of vulnerabilities associated with a package."""
    public_vulns = []
    private_vulns = []
    for vuln in vulnerability_nodes:
        if _is_private_vulnerability(vuln):
            private_vulns.append(VulnerabilityFields(**_get_vulnerability_fields(vuln)))
        else:
            public_vulns.append(VulnerabilityFields(**_get_vulnerability_fields(vuln)))
    return public_vulns, private_vulns


def get_package_details(component: Dict) -> PackageDataWithVulnerabilities:
    """Extract package details from given graph response."""
    pkg_node = component.get("package", {})
    version_node = component.get("version", {})
    ecosystem, pkg = _get_pkg_from_graph_version_node(version_node)
    github_details = get_github_details(pkg_node)
    public_vulns, private_vulns = _get_vulnerabilities(component.get("vuln", {}))
    recommended_latest_version = pkg_node.get("latest_non_cve_version", [""])[0]
    licenses = version_node.get("declared_licenses", [])

    latest_version = pkg_node.get("latest_version", [pkg.version])[0]
    return pkg, PackageDataWithVulnerabilities(**pkg.dict(), ecosystem=ecosystem,
                                               latest_version=latest_version,
                                               github=github_details, licenses=licenses,
                                               # (fixme) this is incorrect
                                               url=get_snyk_package_link(ecosystem, pkg.name),
                                               private_vulnerabilities=private_vulns,
                                               public_vulnerabilities=public_vulns,
                                               recommended_version=recommended_latest_version)


def _get_packages_in_batch(dependencies: Tuple[Package], size: int) -> Tuple[Package]:
    """Take Package Tuple and slices it according to size."""
    for i in range(0, len(dependencies), size):
        yield dependencies[i:i + size]


def _has_vulnerability(pkg: PackageDetails) -> bool:
    return pkg and (pkg.public_vulnerabilities or pkg.private_vulnerabilities)


# (fixme) link to snyk package should be identified during ingestion.
def get_snyk_package_link(ecosystem: str, package: str) -> str:
    """Prepare snyk package link based on ecosystem and package name."""
    ecosystem = AGGREGATOR_SETTINGS.snyk_ecosystem_map.get(ecosystem, ecosystem)
    return AGGREGATOR_SETTINGS.snyk_package_url_format.format(ecosystem=ecosystem,
                                                              package=quote(package, safe=''))


class Aggregator:
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
            package_details.append(get_package_details(pkg))
        # covert list of (pkg, package_details) into map
        return dict(package_details)

    def _get_package_details_with_vulnerabilities(self) -> List[Dict[str, object]]:
        """Get package data from graph along with vulnerability."""
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

            logger.info(
                '%s took %0.2f secs for post_gremlin() batch request',
                self._request.external_request_id, time.time() - started_at)
            if result:
                pkgs_with_vuln['result']['data'] += result['result']['data']

        logger.info('%s took %0.2f secs for get_package_details_with_'
                    'vulnerabilities() for total_results %d', self._request.external_request_id,
                    time.time() - time_start, len(pkgs_with_vuln['result']['data']))
        return pkgs_with_vuln['result']['data']

    def _get_denormalized_package_details(self) -> List[PackageDetails]:
        """Pack PackageDetails according to it's dependency graph structure."""
        package_details = []
        ignore = None
        packages_to_ignore = {}
        all_vulnerabilities_to_ignore = {}

        # Check if ignore JSON is provided
        if self._request.ignore:
            ignore = json.loads(self._request.ignore)

        if ignore:
            packages_to_ignore = ignore.get("packages", {})

            # Make a list of all Vulnerability IDs in case a direct dependency
            # is also present as transitive to other dependency.
            all_vulnerabilities_to_ignore = sum(packages_to_ignore.values(), [])

        for package, transitives in self._normalized_packages.dependency_graph.items():
            ignore_all_transitives = False
            ignored_vulnerability_count = 0
            ignored_trans_vulnerability_count = 0
            package_detail = self._normalized_package_details.get(package)

            if package_detail:
                package_detail = package_detail.copy()

                # Checl if current package is availabe in list of packages to be ignored.
                if package_detail.name in packages_to_ignore:

                    # Number of vulnerabilities before ignoring.
                    vuln_before_ignoring = \
                        len(package_detail.public_vulnerabilities) + \
                        len(package_detail.private_vulnerabilities)

                    # If list of vulnerability IDs are provided for current package
                    # then ignore selected vulnerabilities else ignore all
                    if packages_to_ignore[package_detail.name]:
                        public_vulnerabilities = [
                            vuln for vuln in package_detail.public_vulnerabilities
                            if vuln.id not in all_vulnerabilities_to_ignore]
                        private_vulnerabilities = [
                            vuln for vuln in package_detail.private_vulnerabilities
                            if vuln.id not in all_vulnerabilities_to_ignore]

                        # Reassign new vulnerabilities after ignoring selected IDs.
                        package_detail.public_vulnerabilities = public_vulnerabilities
                        package_detail.private_vulnerabilities = private_vulnerabilities

                        # Number of vulnerabilities after ignoring.
                        vuln_after_ignoring = \
                            len(package_detail.public_vulnerabilities) + \
                            len(package_detail.private_vulnerabilities)
                    else:
                        # Ignore all vulnerabilities.
                        ignore_all_transitives = True
                        package_detail.public_vulnerabilities = []
                        package_detail.private_vulnerabilities = []

                        # Set 0 as all vulnerabilities are ignored
                        vuln_after_ignoring = 0

                    # Get number of vulnerabilities ignored in current package.
                    ignored_vulnerability_count = vuln_before_ignoring - vuln_after_ignoring
            else:
                continue  # pragma: no cover
            transitive_details = []

            for transitive in transitives:
                if transitive in self._normalized_packages.dependency_graph:
                    continue
                transitive_detail = self._normalized_package_details.get(transitive)

                if _has_vulnerability(transitive_detail):
                    transitive_detail = transitive_detail.copy()

                    # Number of transitive vulnerabilities before ignoring.
                    trans_vuln_before_ignoring = \
                        len(transitive_detail.public_vulnerabilities) + \
                        len(transitive_detail.private_vulnerabilities)

                    # User asked to ignore all vulnerabilities of direct dependency
                    # hence all transitive vulnerabilities are also ignored.
                    if ignore_all_transitives:
                        ignored_trans_vulnerability_count += trans_vuln_before_ignoring
                        continue

                    # Ignore selected vulnerabilities
                    trans_public_vulnerabilities = [
                        vuln for vuln in transitive_detail.public_vulnerabilities
                        if vuln.id not in all_vulnerabilities_to_ignore]
                    trans_private_vulnerabilities = [
                        vuln for vuln in transitive_detail.private_vulnerabilities
                        if vuln.id not in all_vulnerabilities_to_ignore]

                    trans_public_vuln_after_ignoring = 0
                    if trans_public_vulnerabilities:
                        # Reassign new public vulnerabilities after ignoring selected IDs.
                        transitive_detail.public_vulnerabilities = trans_public_vulnerabilities

                        # Number of public vulnerabilities after ignoring.
                        trans_public_vuln_after_ignoring = \
                            len(transitive_detail.public_vulnerabilities)

                    trans_private_vuln_after_ignoring = 0
                    if trans_private_vulnerabilities:
                        # Reassign new private vulnerabilities after ignoring selected IDs.
                        transitive_detail.private_vulnerabilities = trans_private_vulnerabilities

                        # Number of private vulnerabilities after ignoring.
                        trans_private_vuln_after_ignoring = \
                            len(transitive_detail.private_vulnerabilities)

                    # Get number of transitive vulnerabilities ignored in current package.
                    ignored_trans_vulnerability_count += trans_vuln_before_ignoring - (
                            trans_public_vuln_after_ignoring + trans_private_vuln_after_ignoring)

                    if not trans_public_vulnerabilities and not trans_private_vulnerabilities:
                        # Skip the iteration if no vulnerabilities are left after ignoring.
                        continue
                else:
                    continue  # pragma: no cover

                transitive_details.append(transitive_detail)

            package_detail.ignored_vulnerability_count = ignored_vulnerability_count
            package_detail.ignored_trans_vulnerability_count = ignored_trans_vulnerability_count
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

    def fetch_details(self):
        """Fetch package & vulnerability info from graph."""
        self._normalized_package_details = self.get_package_details_from_graph()

    def get_result(self) -> StackAggregatorResult:
        """Aggregate stack data."""
        # denormalize package details according to request.dependencies relations
        package_details = self._get_denormalized_package_details()
        unknown_dependencies = self._get_direct_unknown_packages()
        started_at = time.time()

        license_analysis = get_license_analysis_for_stack(package_details)

        logger.info(
            '%s took %0.2f secs for get_license_analysis_for_stack()',
            self._request.external_request_id, time.time() - started_at)
        return StackAggregatorResult(**self._request.dict(exclude={'packages'}),
                                     analyzed_dependencies=package_details,
                                     unknown_dependencies=unknown_dependencies,
                                     license_analysis=license_analysis,
                                     registration_link=AGGREGATOR_SETTINGS.snyk_signin_url)

    def initiate_unknown_package_ingestion(self):
        """Ingestion of Unknown dependencies."""
        ecosystem = self._normalized_packages.ecosystem
        pkg_list = self.get_all_unknown_packages()
        unknown_pkgs = set(map(lambda pkg: ingestion_utils.Package(package=pkg.name,
                                                                   version=pkg.version), pkg_list))
        try:
            unknown_package_flow(ecosystem, unknown_pkgs)
        except Exception as e:
            logger.error('Unknown ingestion failed with %s', e)
        else:
            logger.debug('Unknown ingestion executed for %s packages in %s ecosystem',
                         len(pkg_list), ecosystem)


class StackAggregator:
    """Aggregate stack data from components."""

    @staticmethod
    def process_request(request: Dict) -> Aggregator:
        """Task code."""
        request = StackAggregatorRequest(**request)

        # Always generate registered user report for the given stack, API server
        # shall filter the report fields based on registration status.
        # This will avoid analysis of stack upon user registration.
        if request.ecosystem == 'golang':
            normalized_packages = GoNormalizedPackages(request.packages, request.ecosystem)
            aggregator = GoAggregator(request, normalized_packages)
        else:
            normalized_packages = NormalizedPackages(request.packages, request.ecosystem)
            aggregator = Aggregator(request, normalized_packages)
        aggregator.fetch_details()
        return aggregator

    @staticmethod
    def execute(request: Dict, persist=True):
        """Task code."""
        # (fixme): Use timestamp instead of str representation.
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
            logger.info(
                '%s Aggregation process completed, result persisted into RDS',
                output.external_request_id)

        aggregator.initiate_unknown_package_ingestion()
        # result attribute is added to keep a compatibility with v1
        # otherwise metric accumulator related handling has to be
        # customized for v2.

        return {'aggregation': 'success',
                'external_request_id': output.external_request_id,
                'result': output_dict}


class GoAggregator(Aggregator):
    """GoAggregator is a Superset of Aggregator with Golang Added func."""

    def __init__(self, request: StackAggregatorRequest = None,
                 normalized_packages: GoNormalizedPackages = None):
        """Initialize common fields."""
        super().__init__(request, normalized_packages)
        self._normalized_packages = normalized_packages
        self.filtered_vul = {}

    def _get_package_details_with_vulnerabilities(self) -> List[Dict[str, object]]:
        """Get package data from graph along with vulnerability."""
        get_package_details_with_vul_query = """
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
        packages = self._normalized_packages.all_deps_without_pseudo
        packages = [pkg.dict(exclude={'dependencies'}) for pkg in packages]
        data = self._get_data_from_graph(
            packages, get_package_details_with_vul_query, '_get_pkg_details_with_vuls')
        return data['result']['data']

    def get_package_details_from_graph(self) -> Dict[Package, PackageDetails]:
        """Get dependency data from graph."""
        graph_response = self._get_package_details_with_vulnerabilities()
        package_details: List[Tuple[Package, PackageDetails]] = []
        for pkg in graph_response:
            package_details.append(get_package_details(pkg))

        psedo_pkgs_data = self._get_package_details_from_graph_for_pseudo_versions()
        for pseudo_pkg in psedo_pkgs_data:
            pseudo_pkg_details = self._get_golang_package_details(pseudo_pkg)
            package_details.append(pseudo_pkg_details)

        # covert list of (pkg, package_details) into map
        return dict(package_details)

    def _get_data_from_graph(self, packages, query, caller=None) -> Dict:
        """Get package data from graph along with vulnerability."""
        logger.info('Executing _get_data_from_db.')
        time_start = time.time()
        pkgs_with_vuln = {
            "result": {
                "data": []
            }
        }
        # get rid of leading white spaces
        query = inspect.cleandoc(query)
        bindings = {
            'ecosystem': self._normalized_packages.ecosystem,
            'packages': []
        }
        # call gremlin in batches of GREMLIN_QUERY_SIZE
        for packages in _get_packages_in_batch(packages, GREMLIN_QUERY_SIZE):
            bindings['packages'] = list(packages)
            started_at = time.time()
            result = post_gremlin(query, bindings)
            logger.info(
                '%s took %0.2f secs for post_gremlin() batch request',
                self._request.external_request_id, time.time() - started_at)
            if result:
                pkgs_with_vuln['result']['data'] += result['result']['data']

        logger.info('%s took %0.2f secs for %s'
                    'for total_results %d', self._request.external_request_id,
                    time.time() - time_start, caller, len(pkgs_with_vuln['result']['data']))
        return pkgs_with_vuln

    def _filter_vulnerable_packages(self, vulnerabilities: List) -> Dict:
        """Filter out vulnerabilities whose commit sha is out of vuln_commit_rules."""
        logger.info('Executing filter_vulnerable_packages')

        filter_vulnerabilities = defaultdict(list)
        gh = GithubUtils()
        for vuln in vulnerabilities:
            package_name = vuln.get('package_name', [None])[0]
            vuln_rules = vuln.get('vuln_commit_date_rules', [None])[0]
            pseudo_version = self._normalized_packages.version_map.get(package_name)
            if not pseudo_version:
                logger.debug("Not a Pseudo Version.")
                continue
            time_stamp = gh.extract_timestamp(pseudo_version)
            if all([vuln_rules, time_stamp,
                    gh._is_commit_date_in_vuln_range(time_stamp, vuln_rules)]):
                filter_vulnerabilities[package_name].append(vuln)
        return filter_vulnerabilities

    def _get_golang_package_details(self, pkg_node) -> Tuple[Package, PackageDetails]:
        """Get Pseudo Golang Package Details."""
        pkg_name = pkg_node.get('name', [None])[0]
        ecosystem = pkg_node.get('ecosystem', [''])[0]
        pkg = Package(name=pkg_name, version=self._normalized_packages.version_map[pkg_name])
        latest_version = pkg_node.get('latest_version', [''])[0]
        public_vulns, private_vulns = _get_vulnerabilities(
            self.filtered_vul.get(pkg_name, []))
        recommended_latest_version = pkg_node.get("latest_non_cve_version", [""])[0]
        pkg_details = PackageDataWithVulnerabilities(
            **pkg.dict(),
            ecosystem=ecosystem,
            latest_version=latest_version,
            github={},
            licenses=[],
            url=get_snyk_package_link(ecosystem, pkg_name),
            private_vulnerabilities=private_vulns,
            public_vulnerabilities=public_vulns,
            recommended_version=recommended_latest_version)

        return pkg, pkg_details

    def _get_package_details_from_graph_for_pseudo_versions(self) -> List:
        """Stack analyses call only for pseudo version applicable for golang."""
        logger.debug('Executing get_batch_sa_data_for_pseudo_version')
        get_modules_query = """
                        g.V().has('snyk_ecosystem', ecosystem)
                        .has('module_name', within(packages))
                        .valueMap()
                        """
        get_vulnerable_pkg_query = """
                        g.V().has('ecosystem', ecosystem)
                        .has('name', within(packages))
                        .valueMap()
                        """
        started_at = time.time()
        # 1. Get All Vulnerabilities attached to Module
        module_vulnerabilities = self._get_data_from_graph(
            self._normalized_packages.modules, get_modules_query, 'module_vulnerabilities')
        module_vulnerabilities = module_vulnerabilities['result']['data']

        # 2. Filter out all Vulnerabilities where commit sha is out of Vulnerability range.
        self.filtered_vul = self._filter_vulnerable_packages(module_vulnerabilities)

        # 3. ADD Package Meta Data sourced from DB
        pckg_response = self._get_data_from_graph(
            tuple(self.filtered_vul.keys()), get_vulnerable_pkg_query, 'pckg_response')
        elapsed_time = time.time() - started_at
        logger.info("It took %s to fetch pseudo version results.", elapsed_time)

        return pckg_response['result']['data']

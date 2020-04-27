"""An implementation of stack aggregator.

Gathers component data from the graph database and aggregate the data to be presented
by stack-analyses endpoint

Output: TBD

"""
import datetime
import time
import logging

from typing import Dict, List, Tuple
from src.utils import (select_latest_version, server_create_analysis,
                       post_http_request, GREMLIN_SERVER_URL_REST, persist_data_in_db,
                       GREMLIN_QUERY_SIZE, format_date)
from src.v2.models import (StackAggregatorRequest, GitHubDetails, PackageDetails,
                           BasicVulnerabilityFields, PackageDetailsForFreeTier,
                           Package, LicenseAnalysis, Audit,
                           StackAggregatorResultForFreeTier)
from src.v2.normalized_packages import EPV, NormalizedPackages
from src.v2.license_service import calculate_stack_level_license

logger = logging.getLogger(__file__) # pylint:disable=C0103

def get_recommended_version(ecosystem, name, version):
    """Fetch the recommended version in case of CVEs."""
    query = "g.V().has('ecosystem', '{eco}').has('name', '{pkg}')" \
            ".out('has_version').not(out('has_snyk_cve')).values('version');"\
        .format(eco=ecosystem, pkg=name)
    payload = {'gremlin': query}
    result = post_http_request(url=GREMLIN_SERVER_URL_REST, payload=payload)
    if result:
        versions = result['result']['data']
        if len(versions) == 0:
            return None
    else:
        return None
    rec_version = version
    for ver in versions:
        rec_version = select_latest_version(
            ver,
            rec_version
        )
    if rec_version == version:
        return None
    return rec_version

def is_private_vulnerability(vulnerability_node):
    """Check whether the given node contains private vulnerability."""
    return vulnerability_node.get('snyk_pvt_vulnerability', [True])[0]

def get_vuln_for_free_tier(vuln_node):
    """Get fields associated with free tier users."""
    return {
        'id': vuln_node.get('snyk_vuln_id')[0],
        'cvss': vuln_node.get('cvss_scores', [''])[0],
        'cve_ids': vuln_node.get('snyk_cve_ids'),
        'cvss_v3': vuln_node.get('snyk_cvss_v3')[0],
        'cwes': vuln_node.get('snyk_cwes'),
        'severity': vuln_node.get('severity')[0],
        'title': vuln_node.get('title')[0],
        'url': vuln_node.get('snyk_url')[0],
    }

def get_vuln_for_registered_user(vuln_node):
    """Get fields associated with registered users."""
    info_free_tier = get_vuln_for_free_tier(vuln_node)
    info_for_registered_user = {
        'description': vuln_node.get('description')[0],
        'exploit': vuln_node.get('exploit')[0],
        'malicious': vuln_node.get('malicious', [False])[0],
        'patch_exists': vuln_node.get('patch_exists', [False])[0],
        'fixable': vuln_node.get('fixable', [False])[0],
        'fixed_in': vuln_node.get('snyk_cvss_v3')[0],
    }
    return {**info_free_tier, **info_for_registered_user}

def get_github_details(package_node) -> GitHubDetails:
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

def get_vulnerabilities(vulnerability_nodes):
    """Get list of vulnerabilities associated with a package."""
    public_vulns = []
    private_vulns = []
    for vuln in vulnerability_nodes:
        if is_private_vulnerability(vuln):
            private_vulns.append(BasicVulnerabilityFields(**get_vuln_for_free_tier(vuln)))
        else:
            public_vulns.append(BasicVulnerabilityFields(**get_vuln_for_free_tier(vuln)))
    return public_vulns, private_vulns

def get_epv_from_graph_version_node(version_node) -> EPV:
    """Create EPV instance from version_node."""
    name = version_node.get("pname", [""])[0]
    version = version_node.get("version", [""])[0]
    ecosystem = version_node.get("pecosystem", [""])[0]
    return EPV(ecosystem, name, version)

def extract_component_details(component):
    """Extract package details from given graph response."""
    pkg_node = component.get("package", {})
    version_node = component.get("version", {})
    epv = get_epv_from_graph_version_node(version_node)
    github_details = get_github_details(pkg_node)
    public_vulns, private_vulns = get_vulnerabilities(component.get("cve", {}))
    recommended_latest_version = pkg_node.get("latest_non_cve_version", [""])[0]
    if not recommended_latest_version:
        logger.warning('Fallback to graph query to retrive latest version for '
                       '%s %s %s', epv.ecosystem, epv.package, epv.version)
        recommended_latest_version = get_recommended_version(epv.ecosystem,
                                                             epv.package,
                                                             epv.version)

    licenses = component.get("version", {}).get("declared_licenses", [])

    latest_version = select_latest_version(
        epv.version,
        pkg_node.get("libio_latest_version", [""])[0],
        pkg_node.get("latest_version", [""])[0],
        epv.package
    )
    return epv, PackageDetailsForFreeTier(ecosystem=epv.ecosystem, name=epv.package,
                                          version=epv.version, latest_version=latest_version,
                                          github=github_details, licenses=licenses,
                                          # (fixme) this is incorrect
                                          url=(
                                              'http://snyk.io/{eco}:{pkg}'
                                              .format(eco=epv.ecosystem, pkg=epv.package)),
                                          private_vulnerabilities=private_vulns,
                                          public_vulnerabilities=public_vulns,
                                          recommended_version=recommended_latest_version)


def extract_user_stack_package_licenses(resolved, ecosystem):
    """Extract user stack package licenses."""
    pass

def get_unknown_packages(normalized_package_details, packages) -> List[Package]:
    """Get list of unknown packages from the normalized_package_details."""
    all_dependencies = set(packages.all_dependencies)
    analyzed_dependencies = set(normalized_package_details.keys())
    unknown_dependencies = list()
    for epv in all_dependencies.difference(analyzed_dependencies):
        unknown_dependencies.append(Package(name=epv.package, version=epv.version))
    return unknown_dependencies

def get_license_analysis_for_stack(normalized_package_details) -> LicenseAnalysis:
    """Create LicenseAnalysis from license server."""
    licenses, license_analysis = calculate_stack_level_license(normalized_package_details)
    stack_distinct_licenses = list(set(licenses))
    stack_license_conflict = len(license_analysis.get('f8a_stack_licenses', [])) == 0
    return LicenseAnalysis(total_licenses=len(stack_distinct_licenses),
                           distinct_licenses=stack_distinct_licenses,
                           stack_license_conflict=stack_license_conflict,
                           **license_analysis)

def aggregate_stack_data(normalized_package_details, request, # pylint:disable=R0913
                         packages, persist, current_stack_license):
    """Aggregate stack data."""
    # denormalize package details according to request.dependencies relations
    package_details = _get_denormalized_package_details(request, normalized_package_details)
    unknown_dependencies = get_unknown_packages(normalized_package_details, packages)
    license_analysis = get_license_analysis_for_stack(normalized_package_details)
    transitive_count = len(packages.transitive_dependencies) if request.show_transitive else -1
    return StackAggregatorResultForFreeTier(**request.dict(exclude={'packages'}),
                                            analyzed_dependencies=package_details,
                                            transitive_count=transitive_count,
                                            unknown_dependencies=unknown_dependencies,
                                            recommendation_ready=True,
                                            license_analysis=license_analysis,
                                            registration_link="https://snyk.io/login")


def _get_package_details_query_in_batches(dependencies: Tuple[EPV]):
    batch_query = ("g.V().has('pecosystem', '{eco}').has('pname', '{name}')."
                   "has('version', '{ver}').as('version', 'cve')."
                   "select('version').in('has_version').as('package')."
                   "select('package', 'version', 'cve').by(valueMap())."
                   "by(valueMap()).by(out('has_snyk_cve').valueMap().fold()).fill(epv)")
    query: List[str] = ['epv = []']
    for i, dep in enumerate(dependencies, start=1):
        query.append(batch_query.format(eco=dep.ecosystem, name=dep.package, ver=dep.version))
        if i % GREMLIN_QUERY_SIZE == 0:
            yield ';'.join(query)
            query = ['epv = []']
    if len(query) > 1:
        yield ';'.join(query)

def get_package_details_with_vulnerabilities(dependencies) -> List[Dict[str, object]]:
    """Get package data from graph along with vulnerability."""
    time_start = time.time()
    epvs_with_vuln = {
        "result": {
            "data": []
        }
    }
    for query in _get_package_details_query_in_batches(dependencies):
        # call_gremlin in batch
        payload = {'gremlin': query}
        result = post_http_request(url=GREMLIN_SERVER_URL_REST, payload=payload)
        if result:
            epvs_with_vuln['result']['data'] += result['result']['data']

    logger.info(
        'get_package_details_with_vulnerabilities time: %f total_results %d',
        time.time() - time_start, len(epvs_with_vuln['result']['data']))
    return epvs_with_vuln['result']['data']


def get_package_details_map(graph_response: List[Dict[str, object]]) -> Dict[EPV, PackageDetails]:
    """Transform graph response into PackageDetails map."""
    package_details = []
    for pkg in graph_response:
        package_details.append(extract_component_details(pkg))
    # covert list of (epv, package_details) into map
    return dict(package_details)

def _get_denormalized_package_details(request, package_details_map) -> List[PackageDetails]:
    package_details = []
    for package in request.packages:
        epv = EPV(request.ecosystem, package.name, package.version)
        package_detail = package_details_map.get(epv)
        if package_detail:
            package_detail = package_detail.copy()
        else:
            continue
        transitive_details = []
        for transitive in package.dependencies:
            transitive_epv = EPV(request.ecosystem, transitive.name, transitive.version)
            transitive_detail = package_details_map.get(transitive_epv)
            if transitive_detail:
                transitive_detail = transitive_detail.copy()
            else:
                continue
            transitive_details.append(transitive_detail)
        package_detail.vulnerable_dependencies = transitive_details
        package_details.append(package_detail)
    return package_details

def get_package_details_from_graph(packages: NormalizedPackages) -> List[PackageDetails]:
    """Get dependency data from graph."""
    graph_response = get_package_details_with_vulnerabilities(packages.all_dependencies)
    return get_package_details_map(graph_response)

class StackAggregator:
    """Aggregate stack data from components."""

    @staticmethod
    def execute(request, persist=True):
        """Task code."""
        started_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        request = StackAggregatorRequest(**request)
        external_request_id = request.external_request_id
        # (fixme) multiple license file support
        # current_stack_license = request.get('current_stack_license', {}).get('1', {})
        current_stack_license = []

        normalized_packages = NormalizedPackages(request.packages, request.ecosystem)
        normalized_package_details = get_package_details_from_graph(normalized_packages)

        output = aggregate_stack_data(normalized_package_details, request,
                                      normalized_packages, persist,
                                      current_stack_license)
        output_dict = output.dict()
        ended_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        output_dict["_audit"] = Audit(started_at=started_at, ended_at=ended_at,
                                      version="v2").dict()
        if persist:
            persist_data_in_db(external_request_id=external_request_id,
                               task_result=output_dict, worker='stack_aggregator_v2',
                               started_at=started_at, ended_at=ended_at)
            logger.info("Aggregation process completed for %s."
                        "Result persisted into RDS.", external_request_id)
        # Ingestion of Unknown dependencies
        logger.info("Unknown ingestion flow process initiated.")
        try:
            for dep in output.unknown_dependencies:
                server_create_analysis(request.ecosystem, dep.name, dep.version, api_flow=True,
                                       force=False, force_graph_sync=True)
        except Exception as e: # pylint:disable=W0703,C0103
            logger.error('Ingestion has been failed for %s ', dep['name'])
            logger.error(e)
            pass
        # result attribute is added to keep a compatibility with v1
        # otherwise metric accumulator related handling has to be
        # customized for v2.
        return {"result": output_dict}

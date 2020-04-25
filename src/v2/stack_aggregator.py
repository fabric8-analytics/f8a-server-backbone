"""An implementation of stack aggregator.

Gathers component data from the graph database and aggregate the data to be presented
by stack-analyses endpoint

Output: TBD

"""
from typing import Dict, List, Tuple
import datetime
import json
import time
import logging
from flask import current_app
import requests
import copy
from collections import defaultdict
from src.utils import (select_latest_version, server_create_analysis, LICENSE_SCORING_URL_REST,
                   execute_gremlin_dsl, GREMLIN_SERVER_URL_REST, persist_data_in_db,
                   GREMLIN_QUERY_SIZE, format_date)
from src.v2.models import (StackAggregatorRequest, GitHubDetails, PackageDetails,
                        BasicVulnerabilityFields, PackageDetailsForFreeTier)
from src.v2.normalized_packages import EPV, NormalizedPackages

logger = logging.getLogger(__file__)

def get_recommended_version(ecosystem, name, version):
    """Fetch the recommended version in case of CVEs."""
    query = "g.V().has('ecosystem', '{eco}').has('name', '{pkg}')" \
            ".out('has_version').not(out('has_snyk_cve')).values('version');"\
        .format(eco=ecosystem, pkg=name)
    payload = {'gremlin': query}
    result = execute_gremlin_dsl(url=GREMLIN_SERVER_URL_REST, payload=payload)
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
    return vulnerability_node.get('snyk_pvt_vulnerability', [True])[0]

def get_vuln_for_free_tier(vuln_node):
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
    public_vulns = []
    private_vulns = []
    for vuln in vulnerability_nodes:
        if is_private_vulnerability(vuln):
            private_vulns.append(BasicVulnerabilityFields(**get_vuln_for_free_tier(vuln)))
        else:
            public_vulns.append(BasicVulnerabilityFields(**get_vuln_for_free_tier(vuln)))
    return public_vulns, private_vulns

def get_epv_from_graph_version_node(version_node) -> EPV:
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
        recommended_latest_version = get_recommended_version(ecosystem, name, version)

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
                                     osio_usage_count=version_node.get("osio_usage_count"),
                                     url='http://snyk.io/{eco}:{pkg}'.format(eco=epv.ecosystem, pkg=epv.package),
                                     private_vulnerabilities=private_vulns,
                                     public_vulnerabilities=public_vulns,
                                     recommended_version=recommended_latest_version)


def _extract_conflict_packages(license_service_output):
    """Extract conflict licenses.

    This helper function extracts conflict licenses from the given output
    of license analysis REST service.

    It returns a list of pairs of packages whose licenses are in conflict.
    Note that this information is only available when each component license
    was identified ( i.e. no unknown and no component level conflict ) and
    there was a stack level license conflict.

    :param license_service_output: output of license analysis REST service
    :return: list of pairs of packages whose licenses are in conflict
    """
    license_conflict_packages = []
    if not license_service_output:
        return license_conflict_packages

    conflict_packages = license_service_output.get('conflict_packages', [])
    for conflict_pair in conflict_packages:
        list_pkgs = list(conflict_pair.keys())
        assert len(list_pkgs) == 2
        d = {
            "package1": list_pkgs[0],
            "license1": conflict_pair[list_pkgs[0]],
            "package2": list_pkgs[1],
            "license2": conflict_pair[list_pkgs[1]]
        }
        license_conflict_packages.append(d)

    return license_conflict_packages


def _extract_unknown_licenses(license_service_output):
    """Extract unknown licenses.

    This helper function extracts unknown licenses information from the given
    output of license analysis REST service.

    At the moment, there are two types of unknowns:

    a. really unknown licenses: those licenses, which are not understood by our system.
    b. component level conflicting licenses: if a component has multiple licenses
        associated then license analysis service tries to identify a representative
        license for this component. If some licenses are in conflict, then its
        representative license cannot be identified and this is another type of
        'unknown' !

    This function returns both types of unknown licenses.

    :param license_service_output: output of license analysis REST service
    :return: list of packages with unknown licenses and/or conflicting licenses
    """
    # TODO: reduce cyclomatic complexity
    really_unknown_licenses = []
    lic_conflict_licenses = []
    if not license_service_output:
        return really_unknown_licenses

    # TODO: refactoring
    if license_service_output.get('status', '') == 'Unknown':
        list_components = license_service_output.get('packages', [])
        for comp in list_components:
            license_analysis = comp.get('license_analysis', {})
            if license_analysis.get('status', '') == 'Unknown':
                pkg = comp.get('package', 'Unknown')
                comp_unknown_licenses = license_analysis.get('unknown_licenses', [])
                for lic in comp_unknown_licenses:
                    really_unknown_licenses.append({
                        'package': pkg,
                        'license': lic
                    })

    # TODO: refactoring
    if license_service_output.get('status', '') == 'ComponentLicenseConflict':
        list_components = license_service_output.get('packages', [])
        for comp in list_components:
            license_analysis = comp.get('license_analysis', {})
            if license_analysis.get('status', '') == 'Conflict':
                pkg = comp.get('package', 'Unknown')
                d = {
                    "package": pkg
                }
                comp_conflict_licenses = license_analysis.get('conflict_licenses', [])
                list_conflicting_pairs = []
                for pair in comp_conflict_licenses:
                    assert len(pair) == 2
                    list_conflicting_pairs.append({
                        'license1': pair[0],
                        'license2': pair[1]
                    })
                d['conflict_licenses'] = list_conflicting_pairs
                lic_conflict_licenses.append(d)

    output = {
        'really_unknown': really_unknown_licenses,
        'component_conflict': lic_conflict_licenses
    }
    return output


def _extract_license_outliers(license_service_output):
    """Extract license outliers.

    This helper function extracts license outliers from the given output of
    license analysis REST service.

    :param license_service_output: output of license analysis REST service
    :return: list of license outlier packages
    """
    outliers = []
    if not license_service_output:
        return outliers

    outlier_packages = license_service_output.get('outlier_packages', {})
    for pkg in outlier_packages.keys():
        outliers.append({
            'package': pkg,
            'license': outlier_packages.get(pkg, 'Unknown')
        })

    return outliers


def perform_license_analysis(license_score_list, dependencies):
    """Pass given license_score_list to stack_license analysis and process response."""
    license_url = LICENSE_SCORING_URL_REST + "/api/v1/stack_license"

    payload = {
        "packages": license_score_list
    }
    resp = {}
    flag_stack_license_exception = False
    # TODO: refactoring
    try:
        resp = execute_gremlin_dsl(url=license_url, payload=payload)
        # lic_response.raise_for_status()  # raise exception for bad http-status codes
        if not resp:
            raise requests.exceptions.RequestException
    except requests.exceptions.RequestException:
        current_app.logger.exception("Unexpected error happened while invoking license analysis!")
        flag_stack_license_exception = True

    msg = None
    stack_license = []
    stack_license_status = None
    unknown_licenses = []
    license_conflict_packages = []
    license_outliers = []
    if not flag_stack_license_exception:
        list_components = resp.get('packages', [])
        for comp in list_components:  # output from license analysis
            for dep in dependencies:  # the known dependencies
                if dep.get('name', '') == comp.get('package', '') and \
                                dep.get('version', '') == comp.get('version', ''):
                    dep['license_analysis'] = comp.get('license_analysis', {})

        msg = resp.get('message')
        _stack_license = resp.get('stack_license', None)
        if _stack_license is not None:
            stack_license = [_stack_license]
        stack_license_status = resp.get('status', None)
        unknown_licenses = _extract_unknown_licenses(resp)
        license_conflict_packages = _extract_conflict_packages(resp)
        license_outliers = _extract_license_outliers(resp)

    output = {
        "reason": msg,
        "status": stack_license_status,
        "f8a_stack_licenses": stack_license,
        "unknown_licenses": unknown_licenses,
        "conflict_packages": license_conflict_packages,
        "outlier_packages": license_outliers
    }
    return output, dependencies


def extract_user_stack_package_licenses(resolved, ecosystem):
    """Extract user stack package licenses."""
    epv_set = create_dependency_data_set(resolved, ecosystem)
    user_stack = get_dependency_data(epv_set)
    list_package_licenses = []
    if user_stack is not None:
        for component in user_stack.get('result', []):
            data = component.get("data", None)
            if data:
                component_data = extract_component_details(data[0])
                license_scoring_input = {
                    'package': component_data['name'],
                    'version': component_data['version'],
                    'licenses': component_data['licenses']
                }
                list_package_licenses.append(license_scoring_input)

    return list_package_licenses


def aggregate_stack_data(normalized_package_details, request, packages, persist, transitive_count):
    """Aggregate stack data."""
    # denormalize package details according to request.dependencies relations
    package_details = _get_denormalized_package_details(request, normalized_package_details)
    # TODO(license integration)
    stack_distinct_licenses = []
    license_analysis = dict()
    stack_license_conflict = None

    all_dependencies = set(packages.all_dependencies)
    analyzed_dependencies = set(normalized_package_details.keys())
    unknown_dependencies = list()
    for epv in all_dependencies.difference(analyzed_dependencies):
        unknown_dependencies.append({'name': epv.package, 'version': epv.version})

    analyzed_direct_dependencies = []
    vulnerable_transitives = []
    data = {
            "analyzed_dependencies": package_details,
            "transitive_count": transitive_count,
            "unknown_dependencies": unknown_dependencies,
            "recommendation_ready": True,  # based on the percentage of dependencies analysed
            "total_licenses": len(stack_distinct_licenses),
            "distinct_licenses": list(stack_distinct_licenses),
            "stack_license_conflict": stack_license_conflict,
            "license_analysis": license_analysis,
            # TODO: should be set based on request field
            "registration_status": "unregistered",
            # TODO: read from config
            "registration_link": "https://snyk.io/login"
    }
    data.update(request.dict(exclude={'packages'}))
    return data


def create_dependency_data_set(packages, ecosystem):
    """Create direct and transitive set to reduce calls to graph."""
    unique_epv_dict = {
        "direct": defaultdict(set),
        "transitive": defaultdict(set)
    }

    for pv in packages:
        if pv.get('name') and pv.get('version'):
            key = ecosystem + "|#|" + pv.get('name') + "|#|" + pv.get('version')
            unique_epv_dict['direct'][key] = set()
            for trans_pv in pv.get('deps', []):
                trans_key = ecosystem + "|#|" + trans_pv.get('name') + "|#|" + \
                            trans_pv.get('version')
                unique_epv_dict['transitive'][trans_key].add(key)

    return unique_epv_dict


def add_transitive_details(epv_list, epv_set):
    """Add transitive dict which affects direct dependencies."""
    direct = epv_set['direct']
    transitive = epv_set['transitive']
    result = []

    # Add transitive dict as necessary
    for epv in epv_list['result']['data']:
        epv_str = epv['version']['pecosystem'][0] + "|#|" + \
            epv['version']['pname'][0] + "|#|" + \
            epv['version']['version'][0]

        if epv_str in direct:
            result.append(copy.deepcopy(epv))
        if epv_str in transitive:
            affected_deps = transitive[epv_str]
            dependents = []
            for dep in affected_deps:
                eco, name, version = dep.split("|#|")
                if name and version:
                    dependents.append(
                        {
                            "package": name,
                            "version": version
                        }
                    )
            epv['dependents'] = dependents
            result.append(copy.deepcopy(epv))

    return result


def get_package_version(epv_set: Dict[str, str]) -> List[Tuple[str, str]]:
    """Get package along with version from epv set."""
    # TODO: Use EPV abstraction
    pkgs = []
    for epv, _ in epv_set.items():
        eco, name, ver = epv.split('|#|')
        pkgs.append((name, ver))
    return pkgs

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
        result = execute_gremlin_dsl(url=GREMLIN_SERVER_URL_REST, payload=payload)
        if result:
            epvs_with_vuln['result']['data'] += result['result']['data']

    logger.info('elapsed_time for gremlin calls: {} total {}'.format(time.time() - time_start, len(epvs_with_vuln['result']['data'])))
    return epvs_with_vuln['result']['data']


def find_unknown_deps(epv_data, epv_list, dep_list, unknown_deps_list, is_transitive=False):
    """Find the list of unknown dependencies."""
    for pkg, ver in dep_list:
        known_flag = False
        for knowndep in epv_data:
            version_node = knowndep['version']
            if pkg == knowndep['version']['pname'][0] and ver == knowndep['version']['version'][0]:
                if is_transitive and 'cve' in knowndep:
                    epv_list['result']['data'].append(knowndep)
                if version_node.get('licenses') or version_node.get('declared_licenses'):
                    known_flag = True
                break
        if not known_flag:
            unknown_deps_list.append({'name': pkg, 'version': ver})
    return epv_list, unknown_deps_list


def get_package_details_map(graph_response: List[Dict[str, object]]) -> Dict[EPV, PackageDetails]:
    """
    Transforms the graph response with package, version, vulnerability fields
    to PackageDetails model and maps it with corresponding EPV
    """
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
                transitive_detail = transitive_detail.copy().dict()
            else:
                continue
            transitive_details.append(transitive_detail)
        package_detail.vulnerable_dependencies = transitive_details
        package_details.append(package_detail.dict())
    return package_details

def get_package_details_from_graph(request: StackAggregatorRequest, packages: NormalizedPackages) -> List[PackageDetails]:
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
        unknown_dep_list = []
        show_transitive = request.show_transitive
        external_request_id = request.external_request_id
        # TODO multiple license file support
        # current_stack_license = request.get('current_stack_license', {}).get('1', {})
        current_stack_license = []

        normalized_packages = NormalizedPackages(request.packages, request.ecosystem)
        normalized_package_details = get_package_details_from_graph(request, normalized_packages)

        """ Direct deps can have 0 transitives. This condition is added
        so that in ext, we get to know if deps are 0 or if the transitive flag
        is false """
        if show_transitive == "true":
            transitive_count = finished.get('transitive_count', 0)
        else:
            transitive_count = -1
        output = aggregate_stack_data(normalized_package_details, request, normalized_packages, persist, transitive_count)
        output['license_analysis'].update({
            "current_stack_license": current_stack_license
            })
        unknown_dep_list.extend(output['unknown_dependencies'])
        ended_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        audit = {
            'started_at': started_at,
            'ended_at': ended_at,
            'version': 'v2'
        }
        stack_data = {
            '_audit': audit,
            '_release': 'None:None:None'
        }
        stack_data.update(output)
        if persist:
            logger.info("Aggregation process completed for {}."
                        " Writing to RDS.".format(external_request_id))
            persiststatus = persist_data_in_db(external_request_id=external_request_id,
                                               task_result=stack_data, worker='stack_aggregator_v2',
                                               started_at=started_at, ended_at=ended_at)
        else:
            persiststatus = {'stack_aggregator': 'success',
                             'external_request_id': external_request_id,
                             'result': stack_data}
        # Ingestion of Unknown dependencies
        logger.info("Unknown ingestion flow process initiated.")
        try:
            for dep in unknown_dep_list:
                server_create_analysis(request.ecosystem, dep['name'], dep['version'], api_flow=True,
                                       force=False, force_graph_sync=True)
        except Exception as e:
            logger.error('Ingestion has been failed for ' + dep['name'])
            logger.error(e)
            pass
        return persiststatus

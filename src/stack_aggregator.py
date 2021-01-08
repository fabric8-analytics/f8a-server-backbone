"""An implementation of stack aggregator.

Gathers component data from the graph database and aggregate the data to be presented
by stack-analyses endpoint

Output: TBD

"""
import datetime
import time
from flask import current_app
import requests
import copy
from collections import defaultdict
from src.settings import AggregatorSettings
from src.utils import (select_latest_version, server_create_analysis, LICENSE_SCORING_URL_REST,
                       post_http_request, GREMLIN_SERVER_URL_REST, persist_data_in_db,
                       GREMLIN_QUERY_SIZE, format_date)
import logging

logger = logging.getLogger(__file__)


def get_recommended_version(ecosystem, name, version):
    """Fetch the recommended version in case of CVEs."""
    query = "g.V().has('ecosystem', '{eco}').has('name', '{pkg}')" \
            ".out('has_version').not(out('has_cve')).values('version');"\
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


def extract_component_details(component):
    """Extract details from given component."""
    date = format_date(component.get("package", {}).get("gh_refreshed_on", ["N/A"])[0])
    github_details = {
        "dependent_projects":
            component.get("package", {}).get("libio_dependents_projects", [-1])[0],
        "dependent_repos": component.get("package", {}).get("libio_dependents_repos", [-1])[0],
        "total_releases": component.get("package", {}).get("libio_total_releases", [-1])[0],
        "latest_release_duration":
            str(datetime.datetime.fromtimestamp(component.get("package", {}).get(
                "libio_latest_release", [1496302486.0])[0])),
        "first_release_date": "Apr 16, 2010",
        "issues": {
            "month": {
                "opened": component.get("package", {}).get("gh_issues_last_month_opened", [-1])[0],
                "closed": component.get("package", {}).get("gh_issues_last_month_closed", [-1])[0]
            }, "year": {
                "opened": component.get("package", {}).get("gh_issues_last_year_opened", [-1])[0],
                "closed": component.get("package", {}).get("gh_issues_last_year_closed", [-1])[0]
            }},
        "pull_requests": {
            "month": {
                "opened": component.get("package", {}).get("gh_prs_last_month_opened", [-1])[0],
                "closed": component.get("package", {}).get("gh_prs_last_month_closed", [-1])[0]
            }, "year": {
                "opened": component.get("package", {}).get("gh_prs_last_year_opened", [-1])[0],
                "closed": component.get("package", {}).get("gh_prs_last_year_closed", [-1])[0]
            }},
        "stargazers_count": component.get("package", {}).get("gh_stargazers", [-1])[0],
        "forks_count": component.get("package", {}).get("gh_forks", [-1])[0],
        "refreshed_on": date,
        "open_issues_count": component.get("package", {}).get("gh_open_issues_count", [-1])[0],
        "contributors": component.get("package", {}).get("gh_contributors_count", [-1])[0],
        "size": "N/A"
    }
    used_by = component.get("package", {}).get("libio_usedby", [])
    used_by_list = []
    for epvs in used_by:
        slc = epvs.split(':')
        used_by_dict = {
            'name': slc[0],
            'stars': int(slc[1])
        }
        used_by_list.append(used_by_dict)
    github_details['used_by'] = used_by_list

    code_metrics = {
        "code_lines": component.get("version", {}).get("cm_loc", [-1])[0],
        "average_cyclomatic_complexity":
            component.get("version", {}).get("cm_avg_cyclomatic_complexity", [-1])[0],
        "total_files": component.get("version", {}).get("cm_num_files", [-1])[0]
    }

    cves = []
    recommended_latest_version = None
    name = component.get("version", {}).get("pname", [""])[0]
    version = component.get("version", {}).get("version", [""])[0]
    ecosystem = component.get("version", {}).get("pecosystem", [""])[0]
    if len(component.get("cves", [])) > 0:
        for cve in component.get("cves", []):
            component_cve = {
                'CVE': cve.get('cve_id')[0],
                'CVSS': cve.get('cvss_v2', [''])[0]
            }
            cves.append(component_cve)
        recommended_latest_version = component.get("package", {}).get("latest_non_cve_version", "")
        if not recommended_latest_version:
            recommended_latest_version = get_recommended_version(ecosystem, name, version)

    licenses = component.get("version", {}).get("declared_licenses", [])

    latest_version = select_latest_version(
        version,
        component.get("package", {}).get("libio_latest_version", [""])[0],
        component.get("package", {}).get("latest_version", [""])[0],
        name
    )
    component_summary = {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "licenses": licenses,
        "security": cves,
        "osio_user_count": component.get("version", {}).get("osio_usage_count", 0),
        "latest_version": latest_version,
        "recommended_latest_version": recommended_latest_version,
        "github": github_details,
        "code_metrics": code_metrics
    }
    # Add transitive block for transitive deps
    if component.get('transitive', {}):
        if not cves:
            return None
        else:
            component_summary['transitive'] = component.get('transitive')
    return component_summary


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
        resp = post_http_request(url=license_url, payload=payload)
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


def aggregate_stack_data(stack, manifest_file, ecosystem, deps,
                         manifest_file_path, persist, transitive_count):
    """Aggregate stack data."""
    dependencies = []
    licenses = []
    license_score_list = []
    for component in stack.get('result', []):
        data = component.get("data", None)
        if data:
            component_data = extract_component_details(data[0])
            if component_data:
                # create license dict for license scoring
                license_scoring_input = {
                    'package': component_data['name'],
                    'version': component_data['version'],
                    'licenses': component_data['licenses']
                }
                dependencies.append(component_data)
                licenses.extend(component_data['licenses'])
                license_score_list.append(license_scoring_input)

    stack_distinct_licenses = set(licenses)

    # Call License Scoring to Get Stack License
    if persist:
        license_analysis, dependencies = perform_license_analysis(license_score_list, dependencies)
        stack_license_conflict = len(license_analysis.get('f8a_stack_licenses', [])) == 0
    else:
        license_analysis = dict()
        stack_license_conflict = None

    all_dependencies = {(dependency['package'], dependency['version']) for dependency in deps}
    analyzed_dependencies = {(dependency['name'], dependency['version'])
                             for dependency in dependencies}
    unknown_dependencies = list()
    for name, version in all_dependencies.difference(analyzed_dependencies):
        unknown_dependencies.append({'name': name, 'version': version})

    data = {
            "manifest_name": manifest_file,
            "manifest_file_path": manifest_file_path,
            "user_stack_info": {
                "ecosystem": ecosystem,
                "analyzed_dependencies_count": len(dependencies),
                "analyzed_dependencies": dependencies,
                "transitive_count": transitive_count,
                "unknown_dependencies": unknown_dependencies,
                "unknown_dependencies_count": len(unknown_dependencies),
                "recommendation_ready": True,  # based on the percentage of dependencies analysed
                "total_licenses": len(stack_distinct_licenses),
                "distinct_licenses": list(stack_distinct_licenses),
                "stack_license_conflict": stack_license_conflict,
                "dependencies": deps,
                "license_analysis": license_analysis
            }
    }
    return data


def create_dependency_data_set(resolved, ecosystem):
    """Create direct and transitive set to reduce calls to graph."""
    unique_epv_dict = {
        "direct": defaultdict(set),
        "transitive": defaultdict(set)
    }

    for pv in resolved:
        if pv.get('package') and pv.get('version'):
            key = ecosystem + "|#|" + pv.get('package') + "|#|" + pv.get('version')
            unique_epv_dict['direct'][key] = set()
            for trans_pv in pv.get('deps', []):
                trans_key = ecosystem + "|#|" + trans_pv.get('package') + "|#|" + \
                            trans_pv.get('version')
                unique_epv_dict['transitive'][trans_key].add(key)

    return unique_epv_dict


def remove_duplicate_cve_data(epv_list):
    """Club all CVEs for an EPV."""
    graph_dict = {}
    result = []
    for data in epv_list['result']['data']:
        pv = data.get('version').get('pname')[0] + ":" + \
             data.get('version').get('version')[0]
        if pv not in graph_dict:
            graph_dict[pv] = {}
        graph_dict[pv].update(data)
        if 'cves' not in graph_dict[pv]:
            graph_dict[pv]['cves'] = list()
        if 'cve' in data:
            cve = graph_dict[pv].pop('cve')
            # Fixes Issue
            # https://github.com/fabric8-analytics/fabric8-analytics-vscode-extension/issues/328
            if cve not in graph_dict[pv]['cves']:
                graph_dict[pv]['cves'].append(cve)

    # create a uniform structure for direct and transitive
    for x, y in graph_dict.items():
        z = list()
        z.append(y)
        data = {'data': z}
        result.append(data)

    return result


def add_transitive_details(epv_list, epv_set):
    """Add transitive dict which affects direct dependencies."""
    direct = epv_set['direct']
    transitive = epv_set['transitive']
    result = []

    cve_epv_list = remove_duplicate_cve_data(epv_list)
    # Add transitive dict as necessary
    for data in cve_epv_list:
        epv = data['data'][0]
        epv_str = epv['version']['pecosystem'][0] + "|#|" + \
            epv['version']['pname'][0] + "|#|" + \
            epv['version']['version'][0]

        if epv_str in direct:
            result.append(copy.deepcopy(data))
        if epv_str in transitive:
            affected_deps = transitive[epv_str]
            trans_dict = {
                'isTransitive': True,
                'affected_direct_deps': []
            }
            for dep in affected_deps:
                eco, name, version = dep.split("|#|")
                if name and version:
                    trans_dict['affected_direct_deps'].append(
                        {
                            "package": name,
                            "version": version
                        }
                    )
            epv['transitive'] = trans_dict
            result.append(copy.deepcopy(data))

    return result


def get_tr_dependency_data(epv_set):
    """Get transitive dependency data from graph."""
    query = "epv=[];"
    tr_epv_list = {
        "result": {
            "data": []
        }
    }
    batch_query = "a = g.V().has('pecosystem', '{eco}').has('pname', '{name}')." \
                  "has('version', '{ver}').dedup(); a.clone().as('version')." \
                  "in('has_version').dedup().as('package').select('version')." \
                  "coalesce(out('has_cve').as('cve')." \
                  "select('package','version','cve').by(valueMap())," \
                  "select('package','version').by(valueMap()))." \
                  "fill(epv);"
    i = 1
    epvs = [x for x, y in epv_set['transitive'].items()]
    tr_list = []
    for epv in epvs:
        eco, name, ver = epv.split('|#|')
        tr_list.append((name, ver))
        query += batch_query.format(eco=eco, name=name, ver=ver)
        if i >= GREMLIN_QUERY_SIZE:
            i = 1
            # call_gremlin in batch
            payload = {'gremlin': query}
            result = post_http_request(url=GREMLIN_SERVER_URL_REST, payload=payload)
            if result:
                tr_epv_list['result']['data'] += result['result']['data']
            query = "epv=[];"
        i += 1

    if i > 1:
        payload = {'gremlin': query}
        time_start = time.time()
        result = post_http_request(url=GREMLIN_SERVER_URL_REST, payload=payload)
        logger.info('elapsed_time for gremlin call: {}'.format(time.time() - time_start))
        if result:
            tr_epv_list['result']['data'] += result['result']['data']
    return tr_epv_list, tr_list


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


def get_dependency_data(epv_set):
    """Get dependency data from graph."""
    epv_list = {
        "result": {
            "data": [],
            "unknown_deps": []
        }
    }
    unknown_deps_list = []
    query = "epv=[];"
    batch_query = "a = g.V().has('pecosystem', '{eco}').has('pname', '{name}')." \
                  "has('version', '{ver}').dedup(); a.clone().as('version')." \
                  "in('has_version').dedup().as('package').select('version')." \
                  "coalesce(out('has_cve').as('cve')." \
                  "select('package','version','cve').by(valueMap())," \
                  "select('package','version').by(valueMap()))." \
                  "fill(epv);"
    i = 1
    epvs = [x for x, y in epv_set['direct'].items()]
    dep_list = []
    for epv in epvs:
        eco, name, ver = epv.split('|#|')
        dep_list.append((name, ver))
        query += batch_query.format(eco=eco, name=name, ver=ver)
        if i >= GREMLIN_QUERY_SIZE:
            i = 1
            # call_gremlin in batch
            payload = {'gremlin': query}
            result = post_http_request(url=GREMLIN_SERVER_URL_REST, payload=payload)
            if result:
                epv_list['result']['data'] += result['result']['data']
            query = "epv=[];"
        i += 1

    if i > 1:
        payload = {'gremlin': query}
        result = post_http_request(url=GREMLIN_SERVER_URL_REST, payload=payload)
        if result:
            epv_list['result']['data'] += result['result']['data']

    tr_epv_list, tr_list = get_tr_dependency_data(epv_set)
    transitive_count = len(tr_epv_list['result']['data'])

    # Identification of unknown direct dependencies
    epv_data = epv_list['result']['data']
    epv_list, unknown_deps_list = find_unknown_deps(epv_data, epv_list,
                                                    dep_list, unknown_deps_list)

    # Identification of unknown transitive dependencies
    epv_data = tr_epv_list['result']['data']
    epv_list, unknown_deps_list = find_unknown_deps(epv_data, epv_list,
                                                    tr_list, unknown_deps_list, True)
    result = add_transitive_details(epv_list, epv_set)
    accumulated_data = {'result': result, 'unknown_deps': unknown_deps_list,
                        'transitive_count': transitive_count}
    logger.info('Accumulated data: {}'.format(accumulated_data))
    return accumulated_data


class StackAggregator:
    """Aggregate stack data from components."""

    @staticmethod
    def execute(aggregated=None, persist=True):
        """Task code."""
        started_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        stack_data = []
        unknown_dep_list = []
        show_transitive = aggregated.get('show_transitive')
        external_request_id = aggregated.get('external_request_id')
        # TODO multiple license file support
        current_stack_license = aggregated.get('current_stack_license', {}).get('1', {})

        for result in aggregated['result']:
            resolved = result['details'][0]['_resolved']
            ecosystem = result['details'][0]['ecosystem']
            manifest = result['details'][0]['manifest_file']
            manifest_file_path = result['details'][0]['manifest_file_path']

            epv_set = create_dependency_data_set(resolved, ecosystem)
            finished = get_dependency_data(epv_set)

            """ Direct deps can have 0 transitives. This condition is added
            so that in ext, we get to know if deps are 0 or if the transitive flag
            is false """
            if show_transitive == "true":
                transitive_count = finished.get('transitive_count', 0)
            else:
                transitive_count = -1
            if finished is not None:
                output = aggregate_stack_data(finished, manifest, ecosystem.lower(), resolved,
                                              manifest_file_path, persist, transitive_count)
                if output and output.get('user_stack_info'):
                    output['user_stack_info']['license_analysis'].update({
                        "current_stack_license": current_stack_license
                    })
                stack_data.append(output)
            unknown_dep_list.extend(finished['unknown_deps'])
        ended_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        audit = {
            'started_at': started_at,
            'ended_at': ended_at,
            'version': 'v1'
        }
        stack_data = {
            'stack_data': stack_data,
            '_audit': audit,
            '_release': 'None:None:None'
        }
        if persist:
            logger.info("Aggregation process completed for {}."
                        " Writing to RDS.".format(external_request_id))
            persist_data_in_db(external_request_id=external_request_id,
                               task_result=stack_data, worker='stack_aggregator_v2',
                               started_at=started_at, ended_at=ended_at)
        persiststatus = {'stack_aggregator': 'success',
                         'external_request_id': external_request_id,
                         'result': stack_data}
        # Ingestion of Unknown dependencies
        logger.info("Unknown ingestion flow process initiated.")
        if AggregatorSettings().disable_unknown_package_flow:
            logger.warning('Skipping unknown flow %s', unknown_dep_list)
        else:
            try:
                for dep in unknown_dep_list:
                    server_create_analysis(ecosystem, dep['name'], dep['version'], api_flow=True,
                                           force=False, force_graph_sync=True)
            except Exception as e:
                logger.error('Ingestion has been failed for ' + dep['name'])
                logger.error(e)
                pass

        return persiststatus

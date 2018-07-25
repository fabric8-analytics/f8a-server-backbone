"""Gets Alternate and Companion Components recommendation from the recommendation engine.

It also gives a list of packages that are not known to the recommendation engine for further crowd
sourcing.

Output:
[
    {
        "alternate_packages": {},
        "companion_packages": [
            {
                "cooccurrence_count": 219,
                "cooccurrence_probability": 83.26996197718631,
                "package_name": "org.slf4j:slf4j-api",
                "topic_list": [
                    "logging",
                    "dependency-injection",
                    "api"
                ]
            },
            {
                "cooccurrence_count": 205,
                "cooccurrence_probability": 77.9467680608365,
                "package_name": "org.apache.logging.log4j:log4j-core",
                "topic_list": [
                    "logging",
                    "java"
                ]
            },
            {
                "cooccurrence_count": 208,
                "cooccurrence_probability": 79.08745247148289,
                "package_name": "io.vertx:vertx-web-client",
                "topic_list": [
                    "http",
                    "http-request",
                    "vertx-web-client",
                    "http-response"
                ]
            }
        ],
        "ecosystem": "maven",
        "missing_packages": [],
        "outlier_package_list": [],
        "package_to_topic_dict": {
            "io.vertx:vertx-core": [
                "http",
                "socket",
                "tcp",
                "reactive"
            ],
            "io.vertx:vertx-web": [
                "vertx-web",
                "webapp",
                "auth",
                "routing"
            ]
        },
        "user_persona": "1"
    }
]

"""

from __future__ import division
import json
import datetime
import traceback
import requests
import os
from collections import Counter, defaultdict
import re
import semantic_version as sv
import logging

from utils import (create_package_dict, get_session_retry, select_latest_version,
                   GREMLIN_SERVER_URL_REST, LICENSE_SCORING_URL_REST, Postgres,
                   convert_version_to_proper_semantic,
                   version_info_tuple,
                   is_quickstart_majority)
from stack_aggregator import extract_user_stack_package_licenses
from f8a_worker.models import WorkerResult
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert
from flask import current_app

"""This condition is used to set logger for testing,
as tests don't have the current_app context."""
if current_app:
    _logger = current_app.logger
else:
    _logger = logging.getLogger(__file__)
    _logger.setLevel(level=logging.DEBUG)

session = Postgres().session

danger_word_list = [r"drop\(\)", r"V\(\)", r"count\(\)"]
remove = '|'.join(danger_word_list)
pattern = re.compile(r'(' + remove + ')', re.IGNORECASE)
pattern_to_save = r'[^\w\*\.Xx\-\>\=\<\~\^\|\/\:]'
pattern_n2_remove = re.compile(pattern_to_save)


class GraphDB:
    """Graph database interface."""

    @staticmethod
    def execute_gremlin_dsl(payload):
        """Execute the gremlin query and return the response."""
        try:
            response = get_session_retry().post(GREMLIN_SERVER_URL_REST,
                                                data=json.dumps(payload))

            if response.status_code == 200:
                json_response = response.json()

                return json_response
            else:
                _logger.error("HTTP error {}. Error retrieving Gremlin data.".format(
                    response.status_code))
                return None

        except Exception:
            _logger.error(traceback.format_exc())
            return None

    @staticmethod
    def get_response_data(json_response, data_default):
        """Retrieve data from the JSON response.

        Data default parameters takes what should data to be returned.
        """
        return json_response.get("result", {}).get("data", data_default)

    def get_version_information(self, input_list, ecosystem):
        """Fetch the version information for each of the packages.

        Also remove EPVs with CVEs and ones not present in Graph
        """
        input_packages = [package for package in input_list]
        str_query = "g.V().has('ecosystem',ecosystem).has('name',within(input_packages))" \
                    ".as('pkg').out('has_version')" \
                    ".hasNot('cve_ids').as('ver').select('pkg','ver').by(valueMap()).dedup()"
        payload = {
            'gremlin': str_query,
            'bindings': {
                'ecosystem': ecosystem,
                'input_packages': input_packages
            }
        }

        # Query Gremlin with packages list to get their version information
        gremlin_response = self.execute_gremlin_dsl(payload)
        if gremlin_response is None:
            return []
        response = self.get_response_data(gremlin_response, [{0: 0}])
        return response

    @staticmethod
    def filter_versions(epv_list, input_stack, external_request_id=None, rec_type=None):
        """Filter the EPVs according to following rules.

        First filter fetches only EPVs that
        1. has No CVEs
        2. are Present in Graph
        Apply additional filter based on following. That is sorted based on
        3. Latest Version
        4. Dependents Count in Github Manifest Data
        5. Github Release Date
        """
        # TODO: reduce cyclomatic complexity
        _logger.info("Filtering {} for external_request_id {}".format(
            rec_type, external_request_id))

        pkg_dict = defaultdict(dict)
        new_dict = defaultdict(dict)
        filtered_comp_list = []
        # TODO: refactoring
        for epv in epv_list:
            name = epv.get('pkg', {}).get('name', [''])[0]
            version = epv.get('ver', {}).get('version', [''])[0]
            # needed for maven version like 1.5.2.RELEASE to be converted to
            # 1.5.2-RELEASE for semantic version to work'
            semversion_tuple = version_info_tuple(
                convert_version_to_proper_semantic(version, name))
            input_stack_tuple = version_info_tuple(convert_version_to_proper_semantic(
                input_stack.get(name, ''), name))
            if name and version:
                # Select Latest Version and add to filter_list if
                # latest version is > current version
                latest_version = select_latest_version(
                    version,
                    epv.get('pkg').get('libio_latest_version', [''])[0],
                    epv.get('pkg').get('latest_version', [''])[0],
                    name
                )
                if latest_version and latest_version == version:
                    try:
                        if semversion_tuple >= input_stack_tuple:
                            pkg_dict[name]['latest_version'] = latest_version
                            new_dict[name]['latest_version'] = epv.get('ver')
                            new_dict[name]['pkg'] = epv.get('pkg')
                            filtered_comp_list.append(name)
                    except ValueError:
                        _logger.exception(
                            "Unexpected ValueError while filtering latest version!")
                        pass

                # Check for Dependency Count Attribute. Add Max deps count version
                # if version > current version
                deps_count = epv.get('ver').get('dependents_count', [-1])[0]
                if deps_count > 0:
                    if 'deps_count' not in pkg_dict[name] or \
                                    deps_count > pkg_dict[name].get('deps_count', {}).get(
                                'deps_count', 0):
                        try:
                            if semversion_tuple >= input_stack_tuple:
                                pkg_dict[name]['deps_count'] = {"version": version,
                                                                "deps_count": deps_count}
                                new_dict[name]['deps_count'] = epv.get('ver')
                                new_dict[name]['pkg'] = epv.get('pkg')

                                filtered_comp_list.append(name)
                        except ValueError:
                            _logger.exception(
                                "Unexpected ValueError while filtering dependency count!")
                            pass

                # Check for github release date. Add version with most recent github release date
                gh_release_date = epv.get('ver').get('gh_release_date', [0])[0]
                if gh_release_date > 0.0:
                    if 'gh_release_date' not in pkg_dict[name] or \
                                    gh_release_date > \
                                    pkg_dict[name].get('gh_release_date', {}).get('gh_release_date',
                                                                                  0):
                        try:
                            if semversion_tuple >= input_stack_tuple:
                                pkg_dict[name]['gh_release_date'] = {
                                    "version": version,
                                    "gh_release_date": gh_release_date}
                                new_dict[name]['gh_release_date'] = epv.get('ver')
                                new_dict[name]['pkg'] = epv.get('pkg')
                                filtered_comp_list.append(name)
                        except ValueError:
                            _logger.exception(
                                "Unexpected ValueError while filtering github release date!")
                            pass

        _logger.info(
            "Data Dict new_dict for external_request_id {} is {}"
            .format(external_request_id, new_dict))
        _logger.info(
            "Data List filtered_comp_list for external_request_id {} is {}"
            .format(external_request_id, filtered_comp_list))

        # TODO: refactoring
        new_list = []
        for package, contents in new_dict.items():
            if 'latest_version' in contents:
                new_list.append({"pkg": contents['pkg'], "ver": contents['latest_version']})
            elif 'deps_count' in contents:
                new_list.append({"pkg": contents['pkg'], "ver": contents['deps_count']})
            elif 'gh_release_date' in contents:
                new_list.append({"pkg": contents['pkg'], "ver": contents['gh_release_date']})

        return new_list, filtered_comp_list

    @staticmethod
    def get_topics_for_alt(comp_list, pgm_dict):
        """Get topics from pgm and associate with filtered versions from Graph."""
        for epv in comp_list:
            name = epv.get('pkg', {}).get('name', [''])[0]
            if name:
                for pgm_pkg_key, pgm_list in pgm_dict.items():
                    for pgm_epv in pgm_list:
                        if name == pgm_epv.get('package_name', ''):
                            epv['pkg']['pgm_topics'] = pgm_epv.get('topic_list', [])

        return comp_list

    @staticmethod
    def get_topics_for_comp(comp_list, pgm_list):
        """Get topics from pgm and associate with filtered versions from Graph."""
        for epv in comp_list:
            name = epv.get('pkg', {}).get('name', [''])[0]
            if name:
                for pgm_epv in pgm_list:
                    if name == pgm_epv.get('package_name', ''):
                        epv['pkg']['pgm_topics'] = pgm_epv.get('topic_list', [])
                        epv['pkg']['cooccurrence_probability'] = pgm_epv.get(
                            'cooccurrence_probability', 0)
                        epv['pkg']['cooccurrence_count'] = pgm_epv.get(
                            'cooccurrence_count', 0)

        return comp_list


def invoke_license_analysis_service(user_stack_packages, alternate_packages, companion_packages):
    """Pass given args to stack_license analysis."""
    license_url = LICENSE_SCORING_URL_REST + "/api/v1/stack_license"

    payload = {
        "packages": user_stack_packages,
        "alternate_packages": alternate_packages,
        "companion_packages": companion_packages
    }

    json_response = {}
    try:
        lic_response = get_session_retry().post(license_url, data=json.dumps(payload))
        lic_response.raise_for_status()  # raise exception for bad http-status codes
        json_response = lic_response.json()
    except requests.exceptions.RequestException:
        _logger.exception(
            "Unexpected error happened while invoking license analysis!")
        pass

    return json_response


def apply_license_filter(user_stack_components, epv_list_alt, epv_list_com):
    """License Filter."""
    # TODO: refactoring
    license_score_list_alt = []
    for epv in epv_list_alt:
        license_scoring_input = {
            'package': epv.get('pkg', {}).get('name', [''])[0],
            'version': epv.get('ver', {}).get('version', [''])[0],
            'licenses': epv.get('ver', {}).get('declared_licenses', [])
        }
        license_score_list_alt.append(license_scoring_input)

    # TODO: refactoring
    license_score_list_com = []
    for epv in epv_list_com:
        license_scoring_input = {
            'package': epv.get('pkg', {}).get('name', [''])[0],
            'version': epv.get('ver', {}).get('version', [''])[0],
            'licenses': epv.get('ver', {}).get('declared_licenses', [])
        }
        license_score_list_com.append(license_scoring_input)

    # Call license scoring to find license filters
    la_output = invoke_license_analysis_service(user_stack_components,
                                                license_score_list_alt,
                                                license_score_list_com)

    conflict_packages_alt = conflict_packages_com = []
    if la_output.get('status') == 'Successful' and la_output.get('license_filter') is not None:
        license_filter = la_output.get('license_filter', {})
        conflict_packages_alt = license_filter.get('alternate_packages', {}) \
            .get('conflict_packages', [])
        conflict_packages_com = license_filter.get('companion_packages', {}) \
            .get('conflict_packages', [])

    # TODO: refactoring
    list_pkg_names_alt = []
    for epv in epv_list_alt[:]:
        name = epv.get('pkg', {}).get('name', [''])[0]
        if name in conflict_packages_alt:
            list_pkg_names_alt.append(name)
            epv_list_alt.remove(epv)

    # TODO: refactoring
    list_pkg_names_com = []
    for epv in epv_list_com[:]:
        name = epv.get('pkg', {}).get('name', [''])[0]
        if name in conflict_packages_com:
            list_pkg_names_com.append(name)
            epv_list_com.remove(epv)

    output = {
        'filtered_alt_packages_graph': epv_list_alt,
        'filtered_list_pkg_names_alt': list_pkg_names_alt,
        'filtered_comp_packages_graph': epv_list_com,
        'filtered_list_pkg_names_com': list_pkg_names_com
    }
    _logger.info(
        "License Filter output: {}".format(json.dumps(output)))

    return output


class RecommendationTask:
    """Recommendation task."""

    _analysis_name = 'recommendation_v2'
    description = 'Get Recommendation'
    kronos_ecosystems = ['maven']
    chester_ecosystems = ['npm']
    hpf_ecosystems = ['maven']

    @staticmethod
    def call_insights_recommender(payload):
        """Call the PGM model.

        Calls the PGM model with the normalized manifest information to get
        the relevant packages.
        """
        try:
            # TODO remove hardcodedness for payloads with multiple ecosystems
            if payload and 'ecosystem' in payload[0]:
                quickstarts = False
                if payload[0]['ecosystem'] in RecommendationTask.chester_ecosystems:
                    INSIGHTS_SERVICE_HOST = os.getenv("CHESTER_SERVICE_HOST")
                else:
                    INSIGHTS_SERVICE_HOST = os.getenv("HPF_SERVICE_HOST") + "-" + \
                        payload[0]['ecosystem']
                    if payload[0]['ecosystem'] == 'maven':
                        quickstarts = is_quickstart_majority(
                            payload[0]['package_list'])
                    if quickstarts:
                        INSIGHTS_SERVICE_HOST = os.getenv("PGM_SERVICE_HOST") + "-" + \
                            payload[0]['ecosystem']

                INSIGHTS_URL_REST = "http://{host}:{port}".format(
                    host=INSIGHTS_SERVICE_HOST,
                    port=os.getenv("PGM_SERVICE_PORT"))

                if quickstarts:
                    insights_url = INSIGHTS_URL_REST + "/api/v1/schemas/kronos_scoring"
                else:
                    insights_url = INSIGHTS_URL_REST + "/api/v1/companion_recommendation"
                response = get_session_retry().post(insights_url, json=payload)
                if response.status_code != 200:
                    _logger.error(
                        "HTTP error {}. Error retrieving insights data.".format(
                            response.status_code))
                    return None
                else:
                    json_response = response.json()
                    return json_response
            else:
                _logger.error(
                    'Payload information not passed in the call, Quitting! inights '
                    'recommender\'s call'
                )
        except Exception as e:
            _logger.error("Failed retrieving insights data.")
            _logger.error("%s" % e)
            return None

    def execute(self, arguments=None, persist=True, check_license=False):
        """Execute task."""
        # TODO: reduce cyclomatic complexity
        started_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        results = arguments.get('result', None)
        external_request_id = arguments.get('external_request_id', None)

        input_task_for_insights_recommender = []
        recommendations = []
        # TODO: refactoring
        input_stack = {}
        for result in results:
            temp_input_stack = {d["package"]: d["version"] for d in
                                result.get("details", [])[0].get("_resolved")}
            input_stack.update(temp_input_stack)

        for result in results:
            details = result['details'][0]
            resolved = details['_resolved']
            manifest_file_path = details['manifest_file_path']

            recommendation = {
                'companion': [],
                'alternate': [],
                'usage_outliers': [],
                'manifest_file_path': manifest_file_path
            }
            new_arr = [r['package'] for r in resolved]
            json_object = {
                'ecosystem': details['ecosystem'],
                'unknown_packages_ratio_threshold':
                    float(os.environ.get('UNKNOWN_PACKAGES_THRESHOLD', 0.3)),
                'package_list': new_arr,
                'comp_package_count_threshold': int(os.environ.get(
                        'MAX_COMPANION_PACKAGES', 5))
            }
            if details['ecosystem'] in self.kronos_ecosystems:
                json_object.update({
                    'alt_package_count_threshold': int(os.environ.get('MAX_ALTERNATE_PACKAGES', 2)),
                    'outlier_probability_threshold': float(os.environ.get('OUTLIER_THRESHOLD',
                                                                          0.6)),
                    'user_persona': "1",  # TODO - remove janus hardcoded value
                })
            input_task_for_insights_recommender.append(json_object)

            # Call PGM and get the response
            start = datetime.datetime.utcnow()
            insights_response = self.call_insights_recommender(
                input_task_for_insights_recommender)
            elapsed_seconds = (datetime.datetime.utcnow() -
                               start).total_seconds()
            msg = "It took {t} seconds to get insight's response" \
                  "for external request {e}.".format(t=elapsed_seconds,
                                                     e=external_request_id)
            _logger.info(msg)

            # From PGM response process companion and alternate packages and
            # then get Data from Graph
            # TODO - implement multiple manifest file support for below loop

            if insights_response is not None:
                for insights_result in insights_response:
                    companion_packages = []
                    ecosystem = insights_result['ecosystem']

                    # Get usage based outliers
                    recommendation['usage_outliers'] = \
                        insights_result.get('outlier_package_list', [])

                    # Append Topics for User Stack
                    recommendation['input_stack_topics'] = insights_result.get(
                            'package_to_topic_dict', {})
                    # Add missing packages unknown to PGM
                    recommendation['missing_packages_pgm'] = insights_result.get(
                        'missing_packages', [])
                    for pkg in insights_result['companion_packages']:
                        companion_packages.append(pkg['package_name'])

                    # Get Companion Packages from Graph
                    comp_packages_graph = GraphDB().get_version_information(companion_packages,
                                                                            ecosystem)

                    # Apply Version Filters
                    filtered_comp_packages_graph, filtered_list = GraphDB().filter_versions(
                        comp_packages_graph, input_stack, external_request_id, rec_type="COMPANION")

                    filtered_companion_packages = \
                        set(companion_packages).difference(set(filtered_list))
                    _logger.info(
                        "Companion Packages Filtered for external_request_id {} {}"
                        .format(external_request_id, filtered_companion_packages)
                    )

                    # Get the topmost alternate package for each input package

                    # Create intermediate dict to Only Get Top 1 companion
                    # packages for the time being.
                    temp_dict = {}
                    for pkg_name, contents in insights_result.get('alternate_packages', {}).items():
                        pkg = {}
                        for ind in contents:
                            pkg[ind['package_name']] = ind['similarity_score']
                        temp_dict[pkg_name] = pkg

                    final_dict = {}
                    alternate_packages = []
                    for pkg_name, contents in temp_dict.items():
                        # For each input package
                        # Get only the topmost alternate package from a set of
                        # packages based on similarity score
                        top_dict = dict(Counter(contents).most_common(1))
                        for alt_pkg, sim_score in top_dict.items():
                            final_dict[alt_pkg] = {
                                'version': input_stack[pkg_name],
                                'replaces': pkg_name,
                                'similarity_score': sim_score
                            }
                            alternate_packages.append(alt_pkg)

                    # if alternate_packages:
                    # Get Alternate Packages from Graph
                    alt_packages_graph = GraphDB().get_version_information(
                        alternate_packages, ecosystem)

                    # Apply Version Filters
                    filtered_alt_packages_graph, filtered_list = GraphDB().filter_versions(
                        alt_packages_graph, input_stack, external_request_id, rec_type="ALTERNATE")

                    filtered_alternate_packages = \
                        set(alternate_packages).difference(set(filtered_list))
                    _logger.info(
                        "Alternate Packages Filtered for external_request_id {} {}"
                        .format(external_request_id, filtered_alternate_packages)
                    )
                    if check_license:
                        # apply license based filters
                        list_user_stack_comp = extract_user_stack_package_licenses(
                            resolved, ecosystem)
                        license_filter_output = apply_license_filter(list_user_stack_comp,
                                                                     filtered_alt_packages_graph,
                                                                     filtered_comp_packages_graph)

                        lic_filtered_alt_graph = license_filter_output[
                            'filtered_alt_packages_graph']
                        lic_filtered_comp_graph = license_filter_output[
                            'filtered_comp_packages_graph']
                        lic_filtered_list_alt = license_filter_output['filtered_list_pkg_names_alt']
                        lic_filtered_list_com = license_filter_output['filtered_list_pkg_names_com']
                    else:
                        lic_filtered_alt_graph = filtered_alt_packages_graph
                        lic_filtered_comp_graph = filtered_comp_packages_graph
                        lic_filtered_list_alt = lic_filtered_list_com = list()

                    if len(lic_filtered_list_alt) > 0:
                        s = set(filtered_alternate_packages).difference(set(lic_filtered_list_alt))
                        msg = \
                            "Alternate Packages filtered (licenses) for external_request_id {} {}" \
                            .format(external_request_id, s)
                        _logger.info(msg)

                    if len(lic_filtered_list_com) > 0:
                        s = set(filtered_companion_packages).difference(set(lic_filtered_list_com))
                        msg = "Companion Packages filtered (licenses) for external_request_id {} " \
                              "{}".format(external_request_id, s)
                        _logger.info(msg)

                    # Get Topics Added to Filtered Packages
                    topics_comp_packages_graph = GraphDB(). \
                        get_topics_for_comp(lic_filtered_comp_graph,
                                            insights_result.get('companion_packages', []))

                    # Create Companion Block
                    comp_packages = create_package_dict(topics_comp_packages_graph)
                    recommendation['companion'] = comp_packages

                    # Get Topics Added to Filtered Packages
                    topics_comp_packages_graph = GraphDB(). \
                        get_topics_for_alt(lic_filtered_alt_graph,
                                           insights_result.get('alternate_packages', {}))

                    # Create Alternate Dict
                    alt_packages = create_package_dict(topics_comp_packages_graph, final_dict)
                    recommendation['alternate'] = alt_packages

                recommendations.append(recommendation)
            else:
                return {
                    'recommendation': 'pgm_error',
                    'external_request_id': external_request_id,
                    'message': 'PGM Fetching error'
                }

        ended_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        audit = {'started_at': started_at, 'ended_at': ended_at, 'version': 'v1'}

        task_result = {
            'recommendations': recommendations,
            '_audit': audit,
            '_release': 'None:None:None'
        }

        if persist:
            # Store the result in RDS
            try:
                insert_stmt = insert(WorkerResult).values(
                    worker='recommendation_v2',
                    worker_id=None,
                    external_request_id=external_request_id,
                    analysis_id=None,
                    task_result=task_result,
                    error=False
                )
                do_update_stmt = insert_stmt.on_conflict_do_update(
                    index_elements=['id'],
                    set_=dict(task_result=task_result)
                )
                session.execute(do_update_stmt)
                session.commit()
                return {'recommendation': 'success',
                        'external_request_id': external_request_id,
                        'result': task_result}
            except SQLAlchemyError as e:
                session.rollback()
                return {
                    'recommendation': 'database error',
                    'external_request_id': external_request_id,
                    'message': '%s' % e
                }
        else:
            return {'recommendation': 'success',
                    'external_request_id': external_request_id,
                    'result': task_result}

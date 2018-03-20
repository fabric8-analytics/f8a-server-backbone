"""Various utility functions used across the repo."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import requests
import os
import json
import datetime
import semantic_version as sv
from flask import current_app


GREMLIN_SERVER_URL_REST = "http://{host}:{port}".format(
    host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),
    port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))

LICENSE_SCORING_URL_REST = "http://{host}:{port}".format(
    host=os.environ.get("LICENSE_SERVICE_HOST"),
    port=os.environ.get("LICENSE_SERVICE_PORT"))


# Create Postgres Connection Session


class Postgres:
    """Postgres connection session handler."""

    def __init__(self):
        """Initialize the connection to Postgres database."""
        self.connection = 'postgresql://{user}:{password}@{pgbouncer_host}:{pgbouncer_port}' \
                          '/{database}?sslmode=disable'. \
            format(user=os.getenv('POSTGRESQL_USER'),
                   password=os.getenv('POSTGRESQL_PASSWORD'),
                   pgbouncer_host=os.getenv(
                       'PGBOUNCER_SERVICE_HOST', 'bayesian-pgbouncer'),
                   pgbouncer_port=os.getenv('PGBOUNCER_SERVICE_PORT', '5432'),
                   database=os.getenv('POSTGRESQL_DATABASE'))
        engine = create_engine(self.connection)

        self.Session = sessionmaker(bind=engine)
        self.session = self.Session()

    def session(self):
        """Return the established session."""
        return self.session


def get_osio_user_count(ecosystem, name, version):
    """Send query to the graph database to get # of uses for the provided E+P+V."""
    str_gremlin = "g.V().has('pecosystem','{}').has('pname','{}').has('version','{}').".format(
        ecosystem, name, version)
    str_gremlin += "in('uses').count();"
    payload = {
        'gremlin': str_gremlin
    }

    try:
        response = get_session_retry().post(
            GREMLIN_SERVER_URL_REST, data=json.dumps(payload))
        json_response = response.json()
        return json_response['result']['data'][0]
    except Exception as e:
        current_app.logger.error("Failed retrieving Gremlin data.")
        current_app.logger.error("%r" % e)
        return -1


def create_package_dict(graph_results, alt_dict=None):
    """Convert Graph Results into the Recommendation Dict."""
    pkg_list = []

    for epv in graph_results:
        ecosystem = epv.get('ver', {}).get('pecosystem', [''])[0]
        name = epv.get('ver', {}).get('pname', [''])[0]
        version = epv.get('ver', {}).get('version', [''])[0]
        if ecosystem and name and version:
            # TODO change this logic later to fetch osio_user_count
            osio_user_count = get_osio_user_count(ecosystem, name, version)
            pkg_dict = {
                'ecosystem': ecosystem,
                'name': name,
                'version': version,
                'licenses': epv['ver'].get('declared_licenses', []),
                'latest_version': select_latest_version(
                    version,
                    epv['pkg'].get('libio_latest_version', [''])[0],
                    epv['pkg'].get('latest_version', [''])[0],
                    name
                ),
                'security': [],
                'osio_user_count': osio_user_count,
                'topic_list': epv['pkg'].get('pgm_topics', []),
                'cooccurrence_probability': epv['pkg'].get('cooccurrence_probability', 0),
                'cooccurrence_count': epv['pkg'].get('cooccurrence_count', 0)
            }

            github_dict = {
                'dependent_projects': epv['pkg'].get('libio_dependents_projects', [-1])[0],
                'dependent_repos': epv['pkg'].get('libio_dependents_repos', [-1])[0],
                'used_by': [],
                'total_releases': epv['pkg'].get('libio_total_releases', [-1])[0],
                'latest_release_duration': str(datetime.datetime.fromtimestamp(
                    epv['pkg'].get('libio_latest_release',
                                   [1496302486.0])[0])),
                'first_release_date': 'N/A',
                'forks_count': epv['pkg'].get('gh_forks', [-1])[0],
                'stargazers_count': epv['pkg'].get('gh_stargazers', [-1])[0],
                'watchers': epv['pkg'].get('gh_subscribers_count', [-1])[0],
                'contributors': -1,
                'size': 'N/A',
                'issues': {
                    'month': {
                        'closed': epv['pkg'].get('gh_issues_last_month_closed', [-1])[0],
                        'opened': epv['pkg'].get('gh_issues_last_month_opened', [-1])[0]
                    },
                    'year': {
                        'closed': epv['pkg'].get('gh_issues_last_year_closed', [-1])[0],
                        'opened': epv['pkg'].get('gh_issues_last_year_opened', [-1])[0]
                    }
                },
                'pull_requests': {
                    'month': {
                        'closed': epv['pkg'].get('gh_prs_last_month_closed', [-1])[0],
                        'opened': epv['pkg'].get('gh_prs_last_month_opened', [-1])[0]
                    },
                    'year': {
                        'closed': epv['pkg'].get('gh_prs_last_year_closed', [-1])[0],
                        'opened': epv['pkg'].get('gh_prs_last_year_opened', [-1])[0]
                    }
                }
            }
            used_by = epv['pkg'].get("libio_usedby", [])
            used_by_list = []
            for epvs in used_by:
                slc = epvs.split(':')
                used_by_dict = {
                    'name': slc[0],
                    'stars': int(slc[1])
                }
                used_by_list.append(used_by_dict)
            github_dict['used_by'] = used_by_list
            pkg_dict['github'] = github_dict
            pkg_dict['code_metrics'] = {
                "average_cyclomatic_complexity":
                    epv['ver'].get('cm_avg_cyclomatic_complexity', [-1])[0],
                "code_lines": epv['ver'].get('cm_loc', [-1])[0],
                "total_files": epv['ver'].get('cm_num_files', [-1])[0]
            }

            if alt_dict is not None and name in alt_dict:
                pkg_dict['replaces'] = [{
                    'name': alt_dict[name]['replaces'],
                    'version': alt_dict[name]['version']
                }]

            pkg_list.append(pkg_dict)
    return pkg_list


def convert_version_to_proper_semantic(version):
    """Perform Semantic versioning.

    :param version: The raw input version that needs to be converted.
    :return: The semantic version of raw input version.

    Needed for maven version like 1.5.2.RELEASE to be converted to
    1.5.2-RELEASE for semantic version to work'
    """
    if version in ('', '-1', None):
        return '0.0.0'
    vsplit_components = version.split('.')
    len_vsplit = len(vsplit_components)
    if len_vsplit == 1:
        version = version + ".0.0"
    elif len_vsplit == 2:
        version = version + ".0"
    elif len_vsplit == 3 and len(vsplit_components[1].split('-')) == 1 \
            and vsplit_components[-1][0].isalpha():
        version = '.'.join(vsplit_components[
                           :-1]) + '.0.' + vsplit_components[-1]
    version = version.replace('.', '-', 3)
    version = version.replace('-', '.', 2)
    return version


def select_latest_version(input_version='', libio='', anitya=''):
    """Select latest version from input sequence(s)."""
    libio_latest_version = convert_version_to_proper_semantic(libio)
    anitya_latest_version = convert_version_to_proper_semantic(anitya)
    input_version = convert_version_to_proper_semantic(input_version)

    try:
        return_version = input_version
        if sv.Version(libio_latest_version) >= sv.Version(anitya_latest_version)\
                and sv.Version(libio_latest_version) >= sv.Version(input_version):
            return_version = libio

        elif sv.Version(anitya_latest_version) >= sv.Version(libio_latest_version)\
                and sv.Version(anitya_latest_version) >= sv.Version(input_version):
            return_version = anitya

        if return_version == '0.0.0':
            return_version = ''
    except ValueError:
        # In case of failure let's not show any latest version at all
        current_app.logger.exception(
            "Unexpected ValueError while selecting latest version for package {}!"
            .format(package_name))
        return_version = ''
    finally:
        return return_version


def get_session_retry(retries=3, backoff_factor=0.2, status_forcelist=(404, 500, 502, 504),
                      session=None):
    """Set HTTP Adapter with retries to session."""
    session = session or requests.Session()
    retry = Retry(total=retries, read=retries, connect=retries,
                  backoff_factor=backoff_factor, status_forcelist=status_forcelist)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    return session

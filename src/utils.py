"""Various utility functions used across the repo."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import requests
import os
import datetime
import semantic_version as sv
import logging
from flask import current_app
from f8a_worker.models import WorkerResult
from f8a_worker.setup_celery import init_celery
from f8a_worker.setup_celery import init_selinon
from selinon import run_flow
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert
import traceback

logger = logging.getLogger(__file__)
GREMLIN_SERVER_URL_REST = "http://{host}:{port}".format(
    host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),
    port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))

LICENSE_SCORING_URL_REST = "http://{host}:{port}".format(
    host=os.environ.get("LICENSE_SERVICE_HOST", "localhost"),
    port=os.environ.get("LICENSE_SERVICE_PORT", "6162"))

zero_version = sv.Version("0.0.0")
# Create Postgres Connection Session
quickstart_tuple = ("org.wildfly.swarm",
                    "org.springframework.boot",
                    "io.vertx")

GREMLIN_QUERY_SIZE = int(os.environ.get("GREMLIN_QUERY_SIZE", 50))


class Postgres:
    """Postgres connection session handler."""

    def __init__(self):
        """Initialize the connection to Postgres database."""
        self.connection = 'postgresql://{user}:{password}@{pgbouncer_host}:{pgbouncer_port}' \
                          '/{database}?sslmode=disable'. \
            format(user=os.getenv('POSTGRESQL_USER'),
                   password=os.getenv('POSTGRESQL_PASSWORD'),
                   pgbouncer_host=os.getenv('PGBOUNCER_SERVICE_HOST', 'bayesian-pgbouncer'),
                   pgbouncer_port=os.getenv('PGBOUNCER_SERVICE_PORT', '5432'),
                   database=os.getenv('POSTGRESQL_DATABASE'))
        engine = create_engine(self.connection)

        self.Session = sessionmaker(bind=engine)
        self.session = self.Session()

    def session(self):
        """Return the established session."""
        return self.session


session = Postgres().session


def get_osio_user_count(ecosystem, name, version):
    """Send query to the graph database to get # of uses for the provided E+P+V."""
    str_gremlin = "g.V().has('pecosystem','{}').has('pname','{}').has('version','{}').".format(
        ecosystem, name, version)
    str_gremlin += "in('uses').count();"
    payload = {
        'gremlin': str_gremlin
    }

    json_response = execute_gremlin_dsl(url=GREMLIN_SERVER_URL_REST, payload=payload)
    return json_response.get('result').get('data', ['-1'])[0]


def create_package_dict(graph_results, alt_dict=None):
    """Convert Graph Results into the Recommendation Dict."""
    pkg_list = []

    for epv in graph_results:
        ecosystem = epv.get('version', {}).get('pecosystem', [''])[0]
        name = epv.get('version', {}).get('pname', [''])[0]
        version = epv.get('version', {}).get('version', [''])[0]
        if ecosystem and name and version:
            # TODO change this logic later to fetch osio_user_count
            osio_user_count = get_osio_user_count(ecosystem, name, version)
            pkg_dict = {
                'ecosystem': ecosystem,
                'name': name,
                'version': version,
                'licenses': epv['version'].get('declared_licenses', []),
                'latest_version': select_latest_version(
                    version,
                    epv['package'].get('libio_latest_version', [''])[0],
                    epv['package'].get('latest_version', [''])[0]
                ),
                'security': [],
                'osio_user_count': osio_user_count,
                'topic_list': epv['package'].get('pgm_topics', []),
                'cooccurrence_probability': epv['package'].get('cooccurrence_probability', 0),
                'cooccurrence_count': epv['package'].get('cooccurrence_count', 0)
            }

            # TODO: refactoring
            github_dict = {
                'dependent_projects': epv['package'].get('libio_dependents_projects', [-1])[0],
                'dependent_repos': epv['package'].get('libio_dependents_repos', [-1])[0],
                'used_by': [],
                'total_releases': epv['package'].get('libio_total_releases', [-1])[0],
                'latest_release_duration': str(datetime.datetime.fromtimestamp(
                    epv['package'].get('libio_latest_release', [1496302486.0])[0])),
                'first_release_date': 'N/A',
                'forks_count': epv['package'].get('gh_forks', [-1])[0],
                'stargazers_count': epv['package'].get('gh_stargazers', [-1])[0],
                'watchers': epv['package'].get('gh_subscribers_count', [-1])[0],
                'contributors': -1,
                'size': 'N/A',
                'issues': {
                    'month': {
                        'closed': epv['package'].get('gh_issues_last_month_closed', [-1])[0],
                        'opened': epv['package'].get('gh_issues_last_month_opened', [-1])[0]
                    },
                    'year': {
                        'closed': epv['package'].get('gh_issues_last_year_closed', [-1])[0],
                        'opened': epv['package'].get('gh_issues_last_year_opened', [-1])[0]
                    }
                },
                'pull_requests': {
                    'month': {
                        'closed': epv['package'].get('gh_prs_last_month_closed', [-1])[0],
                        'opened': epv['package'].get('gh_prs_last_month_opened', [-1])[0]
                    },
                    'year': {
                        'closed': epv['package'].get('gh_prs_last_year_closed', [-1])[0],
                        'opened': epv['package'].get('gh_prs_last_year_opened', [-1])[0]
                    }
                }
            }
            used_by = epv['package'].get("libio_usedby", [])
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
                    epv['version'].get('cm_avg_cyclomatic_complexity', [-1])[0],
                "code_lines": epv['version'].get('cm_loc', [-1])[0],
                "total_files": epv['version'].get('cm_num_files', [-1])[0]
            }

            if alt_dict is not None and name in alt_dict:
                pkg_dict['replaces'] = [{
                    'name': alt_dict[name]['replaces'],
                    'version': alt_dict[name]['version']
                }]

            pkg_list.append(pkg_dict)
    return pkg_list


def convert_version_to_proper_semantic(version, package_name=None):
    """Perform Semantic versioning.

    : type version: string
    : param version: The raw input version that needs to be converted.
    : type return: semantic_version.base.Version
    : return: The semantic version of raw input version.
    """
    conv_version = sv.Version.coerce('0.0.0')
    try:
        if version in ('', '-1', None):
            version = '0.0.0'
        """Needed for maven version like 1.5.2.RELEASE to be converted to
        1.5.2 - RELEASE for semantic version to work."""
        version = version.replace('.', '-', 3)
        version = version.replace('-', '.', 2)
        # Needed to add this so that -RELEASE is account as a Version.build
        version = version.replace('-', '+', 3)
        conv_version = sv.Version.coerce(version)
    except ValueError:
        current_app.logger.info(
            "Unexpected ValueError for the package {} due to version {}"
            .format(package_name, version))
        pass
    finally:
        return conv_version


def version_info_tuple(version):
    """Return the sem_version information in form of (major, minor, patch, build).

    : type version: semantic_version.base.Version
    : param version: The semantic version whole details are needed.
    : return: A tuple in form of Version.(major, minor, patch, build)
    """
    if isinstance(version, sv.Version):
        return(version.major,
               version.minor,
               version.patch,
               version.build)
    return (0, 0, 0, tuple())


def select_latest_version(input_version='', libio='', anitya='', package_name=None):
    """Select latest version from input sequence(s)."""
    libio_sem_version = convert_version_to_proper_semantic(libio, package_name)
    anitya_sem_version = convert_version_to_proper_semantic(
        anitya, package_name)
    input_sem_version = convert_version_to_proper_semantic(
        input_version, package_name)
    return_version = ''
    try:
        if libio_sem_version == zero_version\
                and anitya_sem_version == zero_version\
                and input_sem_version == zero_version:
            return_version = ''
        else:
            return_version = input_version
            libio_tuple = version_info_tuple(libio_sem_version)
            anitya_tuple = version_info_tuple(anitya_sem_version)
            input_tuple = version_info_tuple(input_sem_version)
            if libio_tuple >= anitya_tuple and libio_tuple >= input_tuple:
                return_version = libio
            elif anitya_tuple >= libio_tuple and anitya_tuple >= input_tuple:
                return_version = anitya
    except ValueError:
        """In case of failure let's not show any latest version at all.
        Also, no generation of stack trace,
        as we are only intersted in the package that is causing the error."""
        current_app.logger.info(
            "Unexpected ValueError while selecting latest version for package {}. Debug:{}"
            .format(package_name,
                    {'input_version': input_version, 'libio': libio, 'anitya': anitya}))
        return_version = ''
        pass
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


def is_quickstart_majority(package_list=[]):
    """Return true if 50% or more packages are from quickstarts.

    param package_list: The list of packages in the payload.
    """
    count_quickstart_pck = 0
    for package_name in package_list:
        if package_name.startswith(quickstart_tuple):
            count_quickstart_pck += 1
    # If 50% or more packages reflect quickstarts, pick kronos.
    # Defaults to Kronos if package_list is empty
    return count_quickstart_pck >= len(package_list) / 2


def persist_data_in_db(external_request_id, task_result, worker):
    """Persist the data in Postgres."""
    try:
        insert_stmt = insert(WorkerResult).values(
            worker=worker, worker_id=None,
            external_request_id=external_request_id, analysis_id=None, task_result=task_result,
            error=False)
        do_update_stmt = insert_stmt.on_conflict_do_update(
            index_elements=['id'],
            set_=dict(task_result=task_result))
        session.execute(do_update_stmt)
        session.commit()
        return {'recommendation': 'success', 'external_request_id': external_request_id,
                'result': task_result}
    except (SQLAlchemyError, Exception) as e:
        logger.error("Error %r." % e)
        session.rollback()
        return {'recommendation': 'database error', 'external_request_id': external_request_id,
                'message': '%s' % e}


def execute_gremlin_dsl(url, payload):
    """Execute the gremlin query and return the response."""
    try:
        response = get_session_retry().post(url=url, json=payload)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(
                "HTTP error {code}. Error retrieving data from {url}.".format(
                    code=response.status_code, url=url))
            return None

    except Exception:
        logger.error(traceback.format_exc())
        return None


def get_response_data(json_response, data_default):
    """Retrieve data from the JSON response.

    Data default parameters takes what should data to be returned.
    """
    return json_response.get("result", {}).get("data", data_default)


def server_run_flow(flow_name, flow_args):
    """Run a flow.

    :param flow_name: name of flow to be run as stated in YAML config file
    :param flow_args: arguments for the flow
    :return: dispatcher ID handling flow
    """
    current_app.logger.debug('Running flow {}'.format(flow_name))
    start = datetime.datetime.now()

    init_celery(result_backend=False)
    init_selinon()
    dispacher_id = run_flow(flow_name, flow_args)

    # compute the elapsed time
    elapsed_seconds = (datetime.datetime.now() - start).total_seconds()
    current_app.logger.debug("It took {t} seconds to start {f} flow.".format(
        t=elapsed_seconds, f=flow_name))
    return dispacher_id


def server_create_analysis(ecosystem, package, version, api_flow=True,
                           force=False, force_graph_sync=False):
    """Create bayesianApiFlow handling analyses for specified EPV.

    :param ecosystem: ecosystem for which the flow should be run
    :param package: package for which should be flow run
    :param version: package version
    :param force: force run flow even specified EPV exists
    :param force_graph_sync: force synchronization to graph
    :return: dispatcher ID handling flow
    """
    args = {
        'ecosystem': ecosystem,
        'name': package,
        'version': version,
        'force': force,
        'force_graph_sync': force_graph_sync
    }

    if api_flow:
        return server_run_flow('bayesianApiFlow', args)
    else:
        return server_run_flow('bayesianFlow', args)


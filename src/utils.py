"""Various utility functions used across the repo."""

import datetime
import logging
import os
import time
import traceback

import requests
import semantic_version as sv

from typing import Dict
from f8a_worker.models import WorkerResult
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests_futures.sessions import FuturesSession
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from src.settings import SETTINGS


logger = logging.getLogger(__name__)


class DatabaseException(Exception):
    """Exception related to RDBS operation failures."""


class GremlinExeception(Exception):
    """Exception related to Gremlin server failures."""


class RequestException(Exception):
    """Exception related to request http library failures."""


logger = logging.getLogger(__file__)

zero_version = sv.Version("0.0.0")
# Create Postgres Connection Session
fmt = "%Y-%m-%dT%H:%M:%S.%f"
worker_count = int(os.getenv('FUTURES_SESSION_WORKER_COUNT', '100'))
_session = FuturesSession(max_workers=worker_count)
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


def format_date(date):
    """Format date to readable format."""
    try:
        if date != 'N/A':
            date = datetime.datetime.strptime(date, '%Y-%m-%d %H:%M:%S').strftime('%d %b %Y')
    except ValueError:
        logger.info("Incorrect value for date -> {}. Ignored".format(date))
        return 'N/A'
    return date


def get_session_retry(retries=3, backoff_factor=0.2, status_forcelist=(404, 500, 502, 504),
                      session=None):
    """Set HTTP Adapter with retries to session."""
    session = session or requests.Session()
    retry = Retry(total=retries, read=retries, connect=retries,
                  backoff_factor=backoff_factor, status_forcelist=status_forcelist)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    return session


def persist_data_in_db(external_request_id, task_result, worker, started_at=None, ended_at=None):
    """Persist the data in Postgres."""
    try:
        insert_stmt = insert(WorkerResult).values(
            worker=worker, worker_id=None,
            external_request_id=external_request_id, analysis_id=None, task_result=task_result,
            error=False, started_at=started_at, ended_at=ended_at)
        do_update_stmt = insert_stmt.on_conflict_do_update(
            index_elements=['id'],
            set_=dict(task_result=task_result))
        session.execute(do_update_stmt)
        session.commit()
    except (SQLAlchemyError, Exception) as e:
        logger.error("Error %r." % e)
        session.rollback()
        raise DatabaseException from e


def post_http_request(url: str, payload: Dict):
    """Post the given payload to url."""
    try:
        response = get_session_retry().post(url=url, json=payload)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error(
            "HTTP error {code}. Error retrieving data from {url}.".format(
                code=response.status_code, url=url))
        raise RequestException from e


def post_gremlin(query: str, bindings: Dict = None) -> Dict:
    """Post the given query and bindings to gremlin endpoint."""
    payload = {
        'gremlin': query,
    }
    if bindings:
        payload['bindings'] = bindings
    try:
        response = get_session_retry().post(url=SETTINGS.gremlin_url, json=payload)
        response.raise_for_status()
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("HTTP error %d. Error retrieving data for %s.",
                     response.status_code, payload)
        raise GremlinExeception from e
    else:
        return response.json()


def select_from_db(external_request_id, worker):
    """
    Read the data from Postgres.

    :param: external_request_id : stack_id
    :param: worker: stack_aggregator / recommender
    """
    try:
        return session.query(WorkerResult)\
            .filter(
                WorkerResult.external_request_id == external_request_id,
                WorkerResult.worker == worker).first()
    except (SQLAlchemyError, Exception) as e:
        logger.error("Error %r." % e)
        session.rollback()
        return {'recommendation': 'database error', 'external_request_id': external_request_id,
                'message': '%s' % e, 'status': 501}


def get_time_delta(audit_data):
    """
    Return Time Delta for Stack Aggregator and Recommender Engine.

    :param audit_data: Audit Data
    :return: Time Delta in Seconds
    """
    if audit_data.get('ended_at') and audit_data.get('started_at'):
        timedelta = (
                datetime.datetime.strptime(audit_data['ended_at'], fmt) -
                datetime.datetime.strptime(audit_data['started_at'], fmt)).total_seconds()
        return timedelta
    return None


def total_time_elapsed(sa_audit_data, external_request_id):
    """
     Return Combined time delta, called in Stack Aggregator Only.

    :param: sa_audit_data: Stack Aggregator Audit Data
    :param: external_request_id: Stack Id
    :return: Time Delta in Seconds
    """
    sa_started_at = sa_audit_data.get('started_at')
    sa_ended_at = sa_audit_data.get('ended_at')
    if sa_started_at is None or sa_ended_at is None:
        return None

    re_db_data = retry(select_from_db,
                       external_request_id=external_request_id,
                       worker='recommendation_v2')

    sa_started_at = datetime.datetime.strptime(sa_started_at, fmt)
    sa_ended_at = datetime.datetime.strptime(sa_ended_at, fmt)
    re_started_at = getattr(re_db_data, 'started_at', sa_started_at)
    re_ended_at = getattr(re_db_data, 'ended_at', sa_ended_at)
    analysis_started_at = min(sa_started_at, re_started_at)
    analysis_ended_at = max(sa_ended_at, re_ended_at)
    # Adding Time Constant, Time includes Resolving and Installation of Dependencies
    return (analysis_ended_at - analysis_started_at).total_seconds() + 45


def retry(func, *args, retry_count=3, **kwargs):
    """Retry Repeatedly."""
    for _ in range(retry_count):
        result = func(*args, **kwargs)
        if result:
            return result
        time.sleep(1)

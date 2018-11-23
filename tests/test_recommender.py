"""Tests for the recommender module."""
from unittest import TestCase
from unittest import mock
import json
import logging

logger = logging.getLogger(__name__)

from src.recommender import RecommendationTask, GraphDB, License, set_valid_cooccurrence_probability
from src.rest_api import app

with open("tests/data/graph_response.json", "r") as f:
    graph_resp = json.load(f)

with open("tests/data/kronos_score_response.json", "r") as f:
    insights_resp = json.load(f)

with open("tests/data/kronos_score_comp_response.json", "r") as f:
    insights_comp_resp = json.load(f)

with open('tests/data/valid_license_analysis.json', 'r') as f:
    license_resp = json.load(f)

with open("tests/data/dependency_response.json", "r") as f:
    dep_resp = json.load(f)


def mocked_requests_get(*args, **_kwargs):
    """Mock the call to the insights service."""
    class MockResponse:
        """Mock response object."""

        def __init__(self, json_data, status_code):
            """Create a mock json response."""
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            """Get the mock json response."""
            return self.json_data

    # return the URL to check whether we are calling the correct service.
    print(args[0])
    return MockResponse({"url": args[0]}, 200)


class TestRecommendationTask(TestCase):
    """Tests for the recommendation task class."""

    @mock.patch('requests.get', side_effect=mocked_requests_get)
    @mock.patch('requests.Session.post', side_effect=mocked_requests_get)
    def test_call_insights_recommender_npm(self, _mock_get, _mock_post):
        """Test if the correct service is called for the correct ecosystem."""
        with app.app_context():
            # Test whether the correct service is called for NPM.
            called_url_json = RecommendationTask.call_insights_recommender([{"ecosystem": "npm"}])
            self.assertTrue('npm-insights' in called_url_json['url'])
            # Now test whether the correct service is called for maven.
            called_url_json = RecommendationTask.call_insights_recommender(
                [{"ecosystem": "maven", "package_list": []}])
            self.assertTrue('pgm' in called_url_json['url'])

            called_url_json = RecommendationTask.call_insights_recommender(
                [{"ecosystem": "maven", "package_list": ["org.slf4j:slf4j-api"]}])
            self.assertTrue('hpf-insights' in called_url_json['url'])


def mocked_response_graph(*args, **_kwargs):
    """Mock the call to the insights service."""
    class MockResponse:
        """Mock response object."""

        def __init__(self, json_data, status_code):
            """Create a mock json response."""
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            """Get the mock json response."""
            return self.json_data

    return MockResponse(graph_resp, 200)


def mocked_response_license(*args, **_kwargs):
    """Mock the call to the execute."""
    class MockResponse:
        """Mock response object."""

        def __init__(self, json_data, status_code):
            """Create a mock json response."""
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            """Get the mock json response."""
            return self.json_data

    if '6162' in str(args[0]):
        return MockResponse(license_resp, 200)
    else:
        return MockResponse(dep_resp, 200)


@mock.patch('src.recommender.RecommendationTask.call_insights_recommender', return_value=[])
def test_execute(_mock_call_insights):
    """Test the function execute."""
    with open("tests/data/stack_aggregator_execute_input.json", "r") as f:
        payload = json.load(f)

    r = RecommendationTask()
    out = r.execute(arguments=payload, persist=False)
    assert out['recommendation'] == "success"
    r = RecommendationTask()
    out = r.execute(arguments=payload, check_license=True, persist=False)
    assert out['recommendation'] == "success"

    out = r.execute(arguments=payload, persist=True)
    assert out['recommendation'] == "database error"


@mock.patch('src.recommender.RecommendationTask.call_insights_recommender',
            side_effect=[insights_comp_resp])
@mock.patch('src.recommender.GraphDB.get_version_information',
            side_effect=[graph_resp['result']['data']])
@mock.patch('src.recommender.License.perform_license_analysis',
            side_effect=license_resp)
def test_execute_with_insights(_mock1, _mock2, _mock3):
    """Test the function execute."""
    with open("tests/data/stack_aggregator_execute_input.json", "r") as f:
        payload = json.load(f)

    r = RecommendationTask()
    out = r.execute(arguments=payload, persist=False, check_license=False)

    assert out['recommendation'] == "success"


@mock.patch('src.recommender.RecommendationTask.call_insights_recommender', return_value=[])
def test_execute_empty_resolved(_mock_call_insights):
    """Test the function execute."""
    with open("tests/data/stack_aggregator_empty_resolved.json", "r") as f:
        payload = json.load(f)

    r = RecommendationTask()
    out = r.execute(arguments=payload, persist=False)

    assert out['recommendation'] == "success"
    assert not out["result"]["recommendations"][0]["companion"]
    assert not out["result"]["recommendations"][0]["alternate"]
    assert not out["result"]["recommendations"][0]["usage_outliers"]

    r = RecommendationTask()
    out = r.execute(arguments=payload, check_license=True, persist=False)
    assert out['recommendation'] == "success"

    out = r.execute(arguments=payload, persist=True)
    assert out['recommendation'] == "database error"


@mock.patch('src.recommender.RecommendationTask.call_insights_recommender', return_value=[])
def test_execute_both_resolved_type(_mock_call_insights):
    """Test the function execute."""
    with open("tests/data/stack_aggregator_combined_input.json", "r") as f:
        payload = json.load(f)

    r = RecommendationTask()
    out = r.execute(arguments=payload, persist=False)
    assert out['recommendation'] == "success"
    assert len(out['result']['recommendations']) == 3
    file_names_expecetd = ["/home/JohnDoe1", "/home/JohnDoe2", "/home/JohnDoe3"]
    file_names_received = [reco["manifest_file_path"] for reco in out['result']['recommendations']]
    assert file_names_received == file_names_expecetd
    r = RecommendationTask()
    out = r.execute(arguments=payload, check_license=True, persist=False)
    assert out['recommendation'] == "success"

    out = r.execute(arguments=payload, persist=True)
    assert out['recommendation'] == "database error"


def test_filter_versions():
    """Test the function filter_versions for latest version."""
    input_stack = {"io.vertx:vertx-web": "3.4.2", "io.vertx:vertx-core": "3.4.2"}

    with open("tests/data/companion_pkg_graph.json", "r") as f:
        companion_packages_graph = json.load(f)

    g = GraphDB()
    filtered_comp_packages_graph, filtered_list = g.filter_versions(companion_packages_graph,
                                                                    input_stack)
    assert len(filtered_comp_packages_graph) > 0
    assert len(filtered_list) > 0


def test_prepare_final_filtered_list():
    """Test the function filter_versions."""
    with open("tests/data/companion_pkg_graph_deps.json", "r") as f:
        comp_pkg_graph = json.load(f)
        deps_pkg_graph = comp_pkg_graph['deps']
        release_pkg_graph = comp_pkg_graph['gh_release']

    g = GraphDB()
    filtered_list = g.prepare_final_filtered_list(deps_pkg_graph)
    assert len(filtered_list) > 0

    filtered_list = g.prepare_final_filtered_list(release_pkg_graph)
    assert len(filtered_list) > 0


@mock.patch('requests.Session.post', side_effect=mocked_response_graph)
def test_get_version_information(_mock1):
    """Test the function get_version_information."""
    out = GraphDB().get_version_information(['io.vertx:vertx-web'], 'maven')
    assert len(out) == 1


def test_get_topics():
    """Test the function get topics."""
    alt_list = GraphDB.get_topics_for_alt(graph_resp['result']['data'],
                                          insights_resp[0]['alternate_packages'])
    comp_list = GraphDB.get_topics_for_comp(graph_resp['result']['data'],
                                            insights_resp[0]['companion_packages'])

    assert alt_list is not None
    assert isinstance(alt_list, list)

    assert comp_list is not None
    assert isinstance(comp_list, list)


def test_get_topmost_alternate():
    """Test the function get topmost alternate recommendation."""
    input_stack = {"io.vertx:vertx-core": "3.4.1"}
    alternate_packages, final_dict = GraphDB.get_topmost_alternate(insights_resp[0], input_stack)

    assert alternate_packages is not None
    assert isinstance(alternate_packages, list)
    assert final_dict is not None
    assert isinstance(final_dict, dict)


@mock.patch('requests.Session.post', side_effect=mocked_response_license)
def test_perform_license_analysis(_mock1):
    """Test license analysis function."""
    with open("tests/data/license_analysis.json", "r") as f:
        payload = json.load(f)
    alt_graph, comp_graph = License.perform_license_analysis(
        resolved=payload['resolved'],
        ecosystem=payload['ecosystem'],
        filtered_alt_packages_graph=payload['filtered_alt_packages_graph'],
        filtered_comp_packages_graph=payload['filtered_comp_packages_graph'],
        filtered_alternate_packages=payload['filtered_alternate_packages'],
        filtered_companion_packages=payload['filtered_companion_packages'],
        external_request_id=payload['external_request_id'])

    assert alt_graph is not None
    assert comp_graph is not None


@mock.patch('src.recommender.License.invoke_license_analysis_service',
            return_value={'status': 'successful', 'license_filter': {}})
def test_apply_license_filter(_mock1):
    """Test the function apply_license_filter."""
    with open('tests/data/epv_list.json', 'r') as f:
        resp = json.load(f)

    out = License.apply_license_filter(None, resp, resp)
    assert isinstance(out, dict)


def test_set_valid_cooccurrence_probability():
    """Test the function set_valid_cooccurrence_probability."""
    input = [{"ecosystem": "maven", "name": "io.fabric8.funktion.connector:connector-smpp",
              "cooccurrence_probability": 'nan'}]
    components = set_valid_cooccurrence_probability(input)
    for component in components:
        assert (component['cooccurrence_probability'] == 100)


if __name__ == '__main__':
    test_execute()
    test_execute_with_insights()
    test_filter_versions()
    test_get_version_information()
    test_apply_license_filter()
    test_perform_license_analysis()
    test_get_topmost_alternate()
    test_get_topics()
    test_prepare_final_filtered_list()

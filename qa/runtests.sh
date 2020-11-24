#!/bin/bash -ex

SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"

pushd "${SCRIPT_DIR}/.." > /dev/null

# test coverage threshold
COVERAGE_THRESHOLD=85

export TERM=xterm
TERM=${TERM:-xterm}

# set up terminal colors
NORMAL=$(tput sgr0)
RED=$(tput bold && tput setaf 1)
GREEN=$(tput bold && tput setaf 2)
YELLOW=$(tput bold && tput setaf 3)

check_python_version() {
    python3 tools/check_python_version.py 3 6
}

check_python_version

PYTHONPATH=$(pwd)/src
export PYTHONPATH

echo "Create Virtualenv for Python deps ..."
function prepare_venv() {
    VIRTUALENV=$(which virtualenv)
    if [ $? -eq 1 ]
    then
        # python36 which is in CentOS does not have virtualenv binary
        VIRTUALENV=$(which virtualenv-3)
    fi

    ${VIRTUALENV} -p python3 venv && source venv/bin/activate
    if [ $? -ne 0 ]
    then
        printf "%sPython virtual environment can't be initialized%s" "${RED}" "${NORMAL}"
        exit 1
    fi
    printf "%sPython virtual environment initialized%s\n" "${YELLOW}" "${NORMAL}"
    pip3 install -U pip
    pip3 install -r requirements.txt

}

[ "$NOVENV" == "1" ] || prepare_venv || exit 1

# now we are surely in the Python virtual environment

pip3 install git+https://github.com/fabric8-analytics/fabric8-analytics-worker.git@fefc764
pip3 install git+https://github.com/fabric8-analytics/fabric8-analytics-utils.git@098d3d6
pip3 install git+https://git@github.com/fabric8-analytics/fabric8-analytics-version-comparator.git#egg=f8a_version_comparator
pip3 install pytest
pip3 install pytest-cov
pip3 install radon==3.0.1

export DEPLOYMENT_PREFIX="${USER}"
export WORKER_ADMINISTRATION_REGION=api
export SENTRY_DSN=''
export POSTGRESQL_USER="user"
export POSTGRESQL_PASSWORD="password"
export POSTGRESQL_DATABASE="dbname"
export PGBOUNCER_SERVICE_HOST="bayesian-pgbouncer"

echo "*****************************************"
echo "*** Unit tests ***"
echo "*****************************************"
PYTHONDONTWRITEBYTECODE=1 python3 "$(which pytest)" --cov=src/ --cov-report term-missing --cov-fail-under=$COVERAGE_THRESHOLD -vv tests/
printf "%stests passed%s\n\n" "${GREEN}" "${NORMAL}"

codecov --token=74b5a608-da00-4b26-aec8-8f7f47489f86

popd > /dev/null

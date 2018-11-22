#!/bin/bash -ex

# test coverage threshold
COVERAGE_THRESHOLD=85

export TERM=xterm
TERM=${TERM:-xterm}

# set up terminal colors
NORMAL=$(tput sgr0)
RED=$(tput bold && tput setaf 1)
GREEN=$(tput bold && tput setaf 2)
YELLOW=$(tput bold && tput setaf 3)

gc() {
  retval=$?
  docker-compose -f docker-compose.yml down -v || :
  exit $retval
}
# trap gc EXIT SIGINT

# Enter local-setup/ directory
# Run local instances for: dynamodb, gremlin-websocket, gremlin-http
function start_backbone_service {
    #pushd local-setup/
    echo "Invoke Docker Compose services"
    docker-compose -f docker-compose.yml up  --force-recreate -d
    #popd
}

start_backbone_service


PYTHONPATH=$(pwd)/src
export PYTHONPATH

echo "Create Virtualenv for Python deps ..."
function prepare_venv() {
    VIRTUALENV=$(which virtualenv)
    if [ $? -eq 1 ]
    then
        # python34 which is in CentOS does not have virtualenv binary
        VIRTUALENV=$(which virtualenv-3)
    fi

    ${VIRTUALENV} -p python3 venv && source venv/bin/activate
    if [ $? -ne 0 ]
    then
        printf "%sPython virtual environment can't be initialized%s" "${RED}" "${NORMAL}"
        exit 1
    fi
    printf "%sPython virtual environment initialized%s\n" "${YELLOW}" "${NORMAL}"
    pip install -U pip
    pip install -r requirements.txt

}

[ "$NOVENV" == "1" ] || prepare_venv || exit 1

# now we are surely in the Python virtual environment

pip install git+https://github.com/fabric8-analytics/fabric8-analytics-worker.git@561636c
pip install pytest
pip install pytest-cov
pip install radon

echo "*****************************************"
echo "*** Cyclomatic complexity measurement ***"
echo "*****************************************"
radon cc -s -a -i venv .

echo "*****************************************"
echo "*** Maintainability Index measurement ***"
echo "*****************************************"
radon mi -s -i venv .

echo "*****************************************"
echo "*** Unit tests ***"
echo "*****************************************"
PYTHONDONTWRITEBYTECODE=1 CHESTER_SERVICE_HOST='npm-insights' PGM_SERVICE_HOST='pgm' HPF_SERVICE_HOST='hpf-insights' PGM_SERVICE_PORT='6006' python3 "$(which pytest)" --cov=src/ --cov-report term-missing --cov-fail-under=$COVERAGE_THRESHOLD -vv tests/
printf "%stests passed%s\n\n" "${GREEN}" "${NORMAL}"

codecov --token=74b5a608-da00-4b26-aec8-8f7f47489f86

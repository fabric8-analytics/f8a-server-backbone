#!/bin/bash -ex

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


export PYTHONPATH=`pwd`/src
echo "Create Virtualenv for Python deps ..."
function prepare_venv() {
    VIRTUALENV=`which virtualenv`
    if [ $? -eq 1 ]; then
        # python34 which is in CentOS does not have virtualenv binary
        VIRTUALENV=`which virtualenv-3`
    fi

    ${VIRTUALENV} -p python3 venv && source venv/bin/activate
    pip install -U pip
    python3 `which pip3` install -r requirements.txt

}

[ "$NOVENV" == "1" ] || prepare_venv || exit 1

`which pip3` install git+https://github.com/fabric8-analytics/fabric8-analytics-worker.git@561636c
`which pip3` install pytest
`which pip3` install pytest-cov
`which pip3` install radon

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
PYTHONDONTWRITEBYTECODE=1 CHESTER_SERVICE_HOST='chester' PGM_SERVICE_HOST='pgm' PGM_SERVICE_PORT='6006' python3 `which pytest` --cov=src/ --cov-report term-missing -vv tests/

#!/usr/bin/bash -ex

gc() {
  retval=$?
  docker-compose -f docker-compose.yml down -v || :
  exit $retval
}
trap gc EXIT SIGINT

# Enter local-setup/ directory
# Run local instances for: dynamodb, gremlin-websocket, gremlin-http
function start_backbone_service {
    #pushd local-setup/
    echo "Invoke Docker Compose services"
    docker-compose -f docker-compose.yml up  --force-recreate -d
    #popd
}

start_backbone_service
yum install -y epel-release
yum install -y gcc git python34-pip python34-requests httpd httpd-devel python34-devel
yum clean all

export PYTHONPATH=`pwd`/src
echo "Create Virtualenv for Python deps ..."
function prepare_venv() {
    VIRTUALENV=`which virtualenv`
    if [ $? -eq 1 ]; then
        # python34 which is in CentOS does not have virtualenv binary
        VIRTUALENV=`which virtualenv-3`
    fi
    ${VIRTUALENV} -p python3 venv && source venv/bin/activate
}
prepare_venv
pip3 install -r requirements.txt
pip3 install git+https://github.com/fabric8-analytics/fabric8-analytics-worker.git@561636c

python3 `which pytest` --cov=src/ --cov-report term-missing -vv tests/

rm -rf venv/

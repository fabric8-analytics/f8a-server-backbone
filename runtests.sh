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

export PYTHONPATH=`pwd`/src

echo "Create Virtualenv for Python deps ..."
virtualenv venv
source venv/bin/activate

pip install -U pip
pip install -r requirements.txt

cd tests
PYTHONDONTWRITEBYTECODE=1 python `which pytest` --cov=../src/ --cov-report term-missing -vv .

rm -rf venv/

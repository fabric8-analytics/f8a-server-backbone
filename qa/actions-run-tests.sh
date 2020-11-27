set -e
pip install -U pip
pip install -r tests/requirements.txt

export DEPLOYMENT_PREFIX="${USER}"
export WORKER_ADMINISTRATION_REGION=api
export SENTRY_DSN=''
export POSTGRESQL_USER="user"
export POSTGRESQL_PASSWORD="password"
export POSTGRESQL_DATABASE="dbname"
export PGBOUNCER_SERVICE_HOST="bayesian-pgbouncer"

py.test --cov=src/ --cov-report=xml --cov-fail-under=85 -vv tests/

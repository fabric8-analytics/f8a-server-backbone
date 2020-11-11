pip install -U pip
pip install -r requirements.txt
pip install git+https://github.com/fabric8-analytics/fabric8-analytics-worker.git@fefc764
pip install git+https://github.com/fabric8-analytics/fabric8-analytics-utils.git@24f8858
pip install git+https://git@github.com/fabric8-analytics/fabric8-analytics-version-comparator.git#egg=f8a_version_comparator
pip install pytest
pip install pytest-cov
pip install radon==3.0.1

export DEPLOYMENT_PREFIX="${USER}"
export WORKER_ADMINISTRATION_REGION=api
export SENTRY_DSN=''
export POSTGRESQL_USER="user"
export POSTGRESQL_PASSWORD="password"
export POSTGRESQL_DATABASE="dbname"
export PGBOUNCER_SERVICE_HOST="bayesian-pgbouncer"

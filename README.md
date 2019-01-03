# f8a-server-backbone

[![Build Status](https://ci.centos.org/job/devtools-f8a-server-backbone-f8a-build-master/badge/icon)](https://ci.centos.org/job/devtools-f8a-server-backbone-f8a-build-master/)

Server backbone service based on a given stack components does two tasks.
 - Stack Aggregation
 - Recommendation

##### Stack Aggregation
Based on the contents of a given payload, it tries to aggregate the data from the Graph.
It then persists the data in the Database and returns a response.

##### Recommendation
Based on the contents of a given payload, it calls Kronos service and gets the recommendation in
terms of
- Outliers
- Alternate Components
- Companion Components

It then persists the above data in the Database and returns a response.

#### How to test:

*  `./runtests.sh`

* curl localhost:<SERVICE_PORT>/api/v1/readiness should return `{}` with status 200


#### Payload Information
```
{
	"external_request_id": "req-id",
	"result": [{
		"summary": [],
		"details": [{
			"ecosystem": "maven",
			"description": "Exposes an HTTP API using Vert.x",
			"_resolved": [{
				"package": "io.vertx:vertx-web",
				"version": "3.4.2"
			}, {
				"package": "io.vertx:vertx-core",
				"version": "3.4.2"
			}],
			"manifest_file_path": "/home/JohnDoe",
			"manifest_file": "pom.xml",
			"declared_licenses": ["Apache License, Version 2.0"],
			"name": "Vert.x - HTTP",
			"dependencies": ["io.vertx:vertx-web 3.4.2", "io.vertx:vertx-core 3.4.2"],
			"version": "1.0.0-SNAPSHOT",
			"devel_dependencies": ["com.jayway.restassured:rest-assured 2.9.0", "io.openshift:openshift-test-utils 2", "org.assertj:assertj-core 3.6.2", "junit:junit 4.12", "io.vertx:vertx-unit 3.4.2", "io.vertx:vertx-web-client 3.4.2", "com.jayway.awaitility:awaitility 1.7.0"],
			"homepage": null
		}],
		"status": "success"
	}]
}
```

#### Recommendation Response
API Endpoint `api/v1/recommender`

```
{
    "external_request_id": "req-id",
    "recommendation": "success"
}
```

#### Recommendation Response
API Endpoint `api/v1/stack_aggregator`

```
{
    "external_request_id": "req-id",
    "stack_aggregator": "success"
}
```

## Unit tests

There's a script named `runtests.sh` that can be used to run all unit tests. The unit test coverage is reported as well by this script.

Usage:

```
./runtests.sh

```

### Footnotes

#### Coding standards

- You can use scripts `run-linter.sh` and `check-docstyle.sh` to check if the code follows [PEP 8](https://www.python.org/dev/peps/pep-0008/) and [PEP 257](https://www.python.org/dev/peps/pep-0257/) coding standards. These scripts can be run w/o any arguments:

```
./run-linter.sh
./check-docstyle.sh
```

The first script checks the indentation, line lengths, variable names, whitespace around operators etc. The second
script checks all documentation strings - its presence and format. Please fix any warnings and errors reported by these
scripts.

#### Code complexity measurement

The scripts `measure-cyclomatic-complexity.sh` and `measure-maintainability-index.sh` are used to measure code complexity. These scripts can be run w/o any arguments:

```
./measure-cyclomatic-complexity.sh
./measure-maintainability-index.sh
```

The first script measures cyclomatic complexity of all Python sources found in the repository. Please see [this table](https://radon.readthedocs.io/en/latest/commandline.html#the-cc-command) for further explanation how to comprehend the results.

The second script measures maintainability index of all Python sources found in the repository. Please see [the following link](https://radon.readthedocs.io/en/latest/commandline.html#the-mi-command) with explanation of this measurement.

You can specify command line option `--fail-on-error` if you need to check and use the exit code in your workflow. In this case the script returns 0 when no failures has been found and non zero value instead.

#### Dead code detection

The script `detect-dead-code.sh` can be used to detect dead code in the repository. This script can be run w/o any arguments:

```
./detect-dead-code.sh
```

Please note that due to Python's dynamic nature, static code analyzers are likely to miss some dead code. Also, code that is only called implicitly may be reported as unused.

Because of this potential problems, only code detected with more than 90% of confidence is reported.

#### Common issues detection

The script `detect-common-errors.sh` can be used to detect common errors in the repository. This script can be run w/o any arguments:

```
./detect-common-errors.sh
```

Please note that only semantical problems are reported.

#### Check for scripts written in BASH

The script named `check-bashscripts.sh` can be used to check all BASH scripts (in fact: all files with the `.sh` extension) for various possible issues, incompatibilities, and caveats. This script can be run w/o any arguments:

```
./check-bashscripts.sh
```

Please see [the following link](https://github.com/koalaman/shellcheck) for further explanation, how the ShellCheck works and which issues can be detected.

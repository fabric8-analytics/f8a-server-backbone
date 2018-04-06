#!/bin/bash

set -ex

. cico_setup.sh

# not needed for tests, but we can check that the image actually builds
build_image
prep(){
	yum -y update
	yum install -y epel-release
	yum install -y postgresql-devel
	yum install -y gcc git python34-pip python34-requests httpd httpd-devel python34-devel
	yum clean all
	pip3 install -U pip
	pip3 install pytest
}

prep

./runtests.sh

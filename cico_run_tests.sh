#!/bin/bash

set -ex

. cico_setup.sh

# not needed for tests, but we can check that the image actually builds
build_image

./runtests.sh

push_image

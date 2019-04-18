#!/bin/bash -ex

export TERM=xterm
TERM=${TERM:-xterm}

# set up terminal colors
NORMAL=$(tput sgr0)
RED=$(tput bold && tput setaf 1)
GREEN=$(tput bold && tput setaf 2)
YELLOW=$(tput bold && tput setaf 3)

PYTHONPATH=$(pwd)/src
export PYTHONPATH

printf "%sCreate Virtualenv for Python deps ..." "${NORMAL}"

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
    pip install -U pip
    pip install -r requirements.txt

}

[ "$NOVENV" == "1" ] || prepare_venv || exit 1

# now we are surely in the Python virtual environment

pdoc --html --overwrite --all-submodules src

printf "%sdocumentation generated%s\n\n" "${GREEN}" "${NORMAL}"

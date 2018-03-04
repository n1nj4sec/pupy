#!/bin/bash

SELF=`readlink -f "$0"`
PUPY=`dirname "$SELF"`/../
PUPY=`readlink -f "$PUPY"`

DOCKER_REPO=${DOCKER_REPO:-"alxchk"}
CLEAN=${CLEAN:-"no"}

if [ ! -z "$REPO" ]; then
    if [ "$REPO" == "local" ]; then
        REPO=""
    else
        REPO="$REPO/"
    fi
else
    REPO="${DOCKER_REPO}/"
fi

echo $PUPY

set -e

start_container() {
    TOOLCHAIN="tc-$1"
    CONTAINER_NAME="build-pupy-$1"
    SOURCES="$2"
    SCRIPT="client/$SOURCES/build-docker.sh"

    (
	echo
	echo "[+] Build $SOURCES with toolchain ${REPO}$TOOLCHAIN"
	NEW=""
	docker container inspect ${CONTAINER_NAME} >/dev/null 2>/dev/null || NEW=1
	if [ ! -z "$NEW" ]; then
	    docker run --name ${CONTAINER_NAME} \
		   -v ${PUPY}:/build/workspace/project ${REPO}${TOOLCHAIN} ${SCRIPT}
	else
	    docker start -ai ${CONTAINER_NAME}
	fi

	if [ "$CLEAN" == "yes" ]; then
	    docker rm ${CONTAINER_NAME}
	fi
	echo
    )
}

if [ ! -z "$1" ] && [ ! -z "$2" ]; then
	start_container $1 $2
else
	start_container windows sources
	start_container linux32 sources-linux
	start_container linux64 sources-linux
	start_container android android_sources
fi

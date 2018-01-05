#!/bin/bash

SELF=`readlink -f "$0"`
PUPY=`dirname "$SELF"`/../
PUPY=`readlink -f "$PUPY"`

REPO=${DOCKER_REPO:-"alxchk"}
CLEAN=${CLEAN:-"yes"}

if [ ! -z "$REPO" ]; then
    if [ "$REPO" == "local" ]; then
	REPO=""
    else
	REPO="$REPO/"
    fi
fi

echo $PUPY

set -e

(
    echo
    echo "[+] Build windows client"
    docker run --name build-pupy-windows \
	   -v $PUPY:/build/workspace/project ${REPO}tc-windows client/sources/build-docker.sh

    if [ "$CLEAN" == "yes" ]; then
	docker rm build-pupy-windows
    fi
    
    echo
)

(
    echo
    echo "[+] Build linux32 client"
    docker run --name build-pupy-linux32 \
	   -v $PUPY:/build/workspace/project ${REPO}tc-linux32 client/sources-linux/build-docker.sh

    if [ "$CLEAN" == "yes" ]; then
	docker rm build-pupy-linux32
    fi

    echo
)

(
    echo
    echo "[+] Build linux64 client"
    docker run --name build-pupy-linux64 \
	   -v $PUPY:/build/workspace/project ${REPO}tc-linux64 client/sources-linux/build-docker.sh

    if [ "$CLEAN" == "yes" ]; then
	docker rm build-pupy-linux64
    fi
    echo
)

(
    echo
    echo "[+] Build android client"
    docker run --name build-pupy-android \
	   -v $PUPY:/build/workspace/project ${REPO}tc-android client/android_sources/build-docker.sh && \

    if [ "$CLEAN" == "yes" ]; then
       docker rm build-pupy-android
    fi
    echo
)

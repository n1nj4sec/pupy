#!/bin/bash

SELF=`readlink -f "$0"`
PUPY=`dirname "$SELF"`
PUPY=`readlink -f "$PUPY"`
TAG=${TAG:-"latest"}

set -e

DOCKER_REPO=${DOCKER_REPO:-"alxchk"}
DOCKER_COMMAND=${DOCKER_COMMAND:-docker}

if [ ! -z "$REPO" ]; then
    if [ "$REPO" == "local" ]; then
        REPO="pupy"
    else
        REPO="$REPO/pupy"
    fi
else
    REPO="${DOCKER_REPO}/pupy"
fi


echo "[+] Build clients"
${PUPY}/client/build-docker.sh
echo

echo "[+] Build pupysh full image (${REPO}:${TAG})"
cd ${PUPY}/pupy && \
    ${DOCKER_COMMAND} build \
        -f ${PUPY}/pupy/conf/Dockerfile.default -t ${REPO}:${TAG} .
echo

echo "[+] Build pupysh environment (pupy-python2-env:${TAG})"
cd ${PUPY}/pupy && \
    ${DOCKER_COMMAND} build \
        -f ${PUPY}/pupy/conf/Dockerfile.env -t pupy-python2-env:${TAG} .
echo

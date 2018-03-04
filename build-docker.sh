#!/bin/bash

SELF=`readlink -f "$0"`
PUPY=`dirname "$SELF"`
PUPY=`readlink -f "$PUPY"`
TAG=${TAG:-"latest"}

set -e

DOCKER_REPO=${DOCKER_REPO:-"alxchk"}

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

echo "[+] Build pupysh (${REPO}:${TAG})"
cd ${PUPY}/pupy && docker build -t ${REPO}:${TAG} .
echo

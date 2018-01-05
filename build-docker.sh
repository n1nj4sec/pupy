#!/bin/bash

SELF=`readlink -f "$0"`
PUPY=`dirname "$SELF"`
PUPY=`readlink -f "$PUPY"`
TAG=${TAG:-"latest"}

set -e

REPO=${DOCKER_REPO:-"alxchk"}

if [ ! -z "$REPO" ]; then
    if [ "$REPO" == "local" ]; then
	REPO=""
    else
	REPO="$REPO/pupy"
    fi
fi


echo "[+] Build clients"
${PUPY}/client/build-docker.sh
echo

echo "[+] Build pupysh (${REPO}:${TAG})"
cd ${PUPY}/pupy && docker build -t ${REPO}:${TAG} .
echo

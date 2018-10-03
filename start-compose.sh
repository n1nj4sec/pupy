#!/bin/sh
THIS=$0
PUPY=`dirname "$0"`
PUPY=`readlink -f ${PUPY}`/pupy
WORKDIR=${1:-$HOME/pupy}
GID=${GID:-`id -g`}
TAG=${TAG:-"unstable"}

set -e

if [ ! -d ${WORKDIR} ]; then
    mkdir -p ${WORKDIR}
fi

if [ ! -z "${UID}" ]; then
    UID=`id -u`
fi

echo "[+] Workdir: ${WORKDIR} [UID=${UID} GID=${GID}]"

cd ${PUPY}

export PUPY UID GID WORKDIR TAG
docker-compose -f conf/docker-compose.yml up -d
exec docker attach pupy

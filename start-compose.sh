#!/bin/sh
THIS=$0
PUPY=`dirname "$0"`
PUPY=`readlink -f ${PUPY}`/pupy
WORKDIR=${1:-$HOME/pupy}
CUID=${UID:-`id -u`}
CGID=${GID:-`id -g`}
TAG=${TAG:-"unstable"}

set -e

if [ ! -d ${WORKDIR} ]; then
    mkdir -p ${WORKDIR}
fi

echo "[+] Workdir: ${WORKDIR} [UID=${CUID} GID=${CGID}]"

cd ${PUPY}

export PUPY CUID CGID WORKDIR TAG
docker-compose -f conf/docker-compose.yml up -d
exec docker attach pupy

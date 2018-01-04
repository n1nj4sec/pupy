#!/bin/sh

SELF=`readlink -f "$0"`
PUPY=`dirname "$SELF"`/../
PUPY=`readlink -f "$PUPY"`

echo $PUPY

docker run -v $PUPY:/build/workspace/project alxchk/tc-windows client/sources/build-docker.sh
docker run -v $PUPY:/build/workspace/project alxchk/tc-linux32 client/sources-linux/build-docker.sh
docker run -v $PUPY:/build/workspace/project alxchk/tc-linux64 client/sources-linux/build-docker.sh

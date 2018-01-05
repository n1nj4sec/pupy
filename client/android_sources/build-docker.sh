#!/bin/sh

SELF=`readlink -f "$0"`
SELFPWD=`dirname "$SELF"`
SRC=${SELFPWD:-`pwd`}

cd $SRC

TEMPLATES=`readlink -f ../../pupy/payload_templates`

rm -f $TEMPLATES/pupy.apk

rm -f buildozer.spec
sed -e "s@%BUILDOZER%@$BUILDOZER_CACHE@" buildozer-docker.spec  >buildozer.spec
buildozer android release

mv $SRC/bin/Wi-Fi-0.1-release-unsigned.apk $TEMPLATES/pupy.apk || exit 1

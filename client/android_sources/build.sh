#!/bin/sh
pip install --user --upgrade git+https://github.com/kivy/buildozer
[ -f buildozer.spec ] && ln -sf buildozer.spec.example buildozer.spec
buildozer android_new release
mv .buildozer/android/platform/build/dists/pupy/bin/Wi-Fi-0.1-release-unsigned.apk \
 ../../pupy/payload_templates/pupy.apk

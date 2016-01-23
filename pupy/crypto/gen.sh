#!/bin/bash
openssl req -new -x509 -keyout server.pem -out cert.pem -days 365 -nodes
keytool -genkey -v -keystore pupy-apk-release-key.keystore -alias pupy_key -storepass pupyp4ssword -keyalg RSA -keysize 2048 -validity 10000

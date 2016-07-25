#!/bin/bash

#pupy ssl certificate
openssl req -new -x509 -keyout server.pem -out cert.pem -days 365 -nodes

#pupy rsa key for transports using RSA
openssl genrsa -out rsa_private_key.pem 4096
pyrsa-priv2pub -i rsa_private_key.pem -o rsa_public_key.pem

#pupy apk release key
keytool -genkey -v -keystore pupy-apk-release-key.keystore -alias pupy_key -storepass pupyp4ssword -keyalg RSA -keysize 2048 -validity 10000


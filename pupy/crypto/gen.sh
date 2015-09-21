#!/bin/bash
openssl req -new -x509 -keyout server.pem -out cert.pem -days 365 -nodes

#!/usr/bin/env bash
openssl genrsa -aes128 -passout file:/tmp/jwtRS256_passphrase.txt -out jwtRS256.key  4096
openssl rsa -in jwtRS256.key -passin file:/tmp/jwtRS256_passphrase.txt -pubout -out jwtRS256.pub
rm /tmp/jwtRS256_passphrase.txt

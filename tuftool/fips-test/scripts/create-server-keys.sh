#!/usr/bin/env bash

set -e

mkdir -p test-keys

openssl genrsa -out test-keys/server.key 2048
openssl req -new -key test-keys/server.key -out test-keys/server.csr -config ./configs/csr.conf.in

# Generate CA certificate
openssl genrsa -out test-keys/ca.key 2048 \
  && openssl req -x509 -new -nodes -key test-keys/ca.key \
    -subj "/CN=bottlerocket/C=US/L=WASHINGTON" -days 1825 -out test-keys/ca.crt

openssl dhparam -out test-keys/dhparam.pem 2098

openssl x509 -req -in test-keys/server.csr -CA test-keys/ca.crt -CAkey test-keys/ca.key \
  -CAcreateserial -out test-keys/server.crt -days 10000 -extensions req_ext \
  -extfile ./configs/csr.conf.in

#!/usr/bin/env bash

# delete everything in the right order. errors are ignored so that this
# script can be used whether or not all of the artifacts exist.
docker stop tuf_srv_ctr || true
docker stop toxiproxy_srv_ctr || true
docker stop toxiproxy_cli_ctr || true
docker rm -f tuf_srv_ctr || true
docker rm -f toxiproxy_srv_ctr || true
docker rm -f toxiproxy_cli_ctr || true
docker rm -f toxy_srv_ctr || true
docker network rm tough_test_network || true
docker rmi -f toxiproxy_cli_img || true
docker rmi -f toxy_srv_img || true

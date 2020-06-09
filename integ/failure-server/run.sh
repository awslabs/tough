#!/usr/bin/env bash
set -eo pipefail

# get the directory where this script is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TUF_REFERENCE_REPO="${DIR}/../../tough/tests/data/tuf-reference-impl"

# these ports and ips are hardcoded in various other places. for now don't
# change them without looking for other occurences of the values.
fileserver_ip=172.12.13.2
fileserver_port=10101
toxiproxy_ip=172.12.13.3
toxiproxy_control=8474
toxiproxy_listen=5050
public_port=3000

# dismantle everything and force rebuilds by deleting images
"${DIR}/teardown.sh"

# rebuild the toxiproxy image
docker build -f "${DIR}/Dockerfile.toxiproxycli" \
  -t toxiproxy_cli_img:latest \
  "${DIR}"

# rebuild the toxi image
docker build -f "${DIR}/Dockerfile.toxy" \
  -t toxy_srv_img:latest \
  "${DIR}"

# create a shared network
docker network create \
  --driver=bridge \
  --subnet=172.12.13.0/24 \
  --ip-range=172.12.13.0/24 \
  --gateway=172.12.13.1 \
  tough_test_network

# a non-toxic fileserver that is serving the tuf reference impl repo
docker run -d \
    -v "${TUF_REFERENCE_REPO}/targets:/content/targets" \
    -v "${TUF_REFERENCE_REPO}/metadata:/content/metadata" \
    -e FOLDER=/content \
    -e SHOW_LISTING=true \
    -e PORT="${fileserver_port}" \
    -p "${fileserver_port}:${fileserver_port}" \
    --network tough_test_network \
    --name tuf_srv_ctr \
    --ip "${fileserver_ip}" \
    halverneus/static-file-server:latest

# start the toxiproxy server that will provide mid-response aborts - points to the fileserver
docker run -d \
    -p "${toxiproxy_control}:${toxiproxy_control}" \
    -p "${toxiproxy_listen}:${toxiproxy_listen}" \
    --name toxiproxy_srv_ctr \
    --network tough_test_network \
    --ip 172.12.13.3 \
    shopify/toxiproxy:2.1.4

# run a one-shot container that sets up the toxiproxy with http calls
sleep 1s
docker run \
    --name toxiproxy_cli_ctr \
    --network tough_test_network \
    --ip 172.12.13.99 \
    toxiproxy_cli_img
 
 # run another server 'in front' of toxiproxy, this one will return occasional 503's
 # and occasionally abort with no data at all
 docker run -d \
    -p "${public_port}:3000" \
    --name toxy_srv_ctr \
    --network tough_test_network \
    toxy_srv_img:latest

echo "**********************************************************************"
echo "the toxic tuf repo is available at http://localhost:${public_port}"

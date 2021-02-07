#!/usr/bin/env bash
set -eo pipefail

# this script sets up three http servers.
#   * fileserver: serves TUF repo files on port 10101.
#   * toxiproxy: serves as a proxy to fileserver on port 10102. introduces mid-response aborts.
#   * toxy: serves as a proxy to toxiproxy on port 10103. introduces 5XX failures.
#
# port 10103 is bound on the host so that the 'toxic' TUF repo can be found at:
#   * http://localhost:10103/metadata
#   * http://localhost:10103/targets

# get the directory where this script is located
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TUF_REFERENCE_REPO="${DIR}/../../tough/tests/data/tuf-reference-impl"

# if we are under cygwin , set a windows style path
# (docker for windows requires windows style paths to work ,it doesn't understand cygwin-style paths)
if [[ "$OSTYPE" == "cygwin" ]]; then
  DIR="$(cygpath --windows ${DIR})"
  TUF_REFERENCE_REPO="$(cygpath --windows ${TUF_REFERENCE_REPO})"
fi


function waitforit() {
  echo "waiting $1 seconds for $2 to start"
  sleep $1
}

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
  tough_test_network

# a fileserver that is serving the tuf reference impl repo on port 10101
docker run -d \
  -v "${TUF_REFERENCE_REPO}/targets:/content/targets" \
  -v "${TUF_REFERENCE_REPO}/metadata:/content/metadata" \
  -e FOLDER=/content \
  -e SHOW_LISTING=true \
  -e PORT="10101" \
  --expose "10101" \
  --network tough_test_network \
  --name tuf_srv_ctr \
  --network-alias "fileserver" \
  halverneus/static-file-server:latest
waitforit 1 fileserver

# start the toxiproxy server that will provide mid-response aborts - points to the fileserver
# this container will serve http on 10102. the service can be controlled at 8472.
docker run -d \
  --expose "8474" \
  --expose "10102" \
  --name toxiproxy_srv_ctr \
  --network tough_test_network \
  --network-alias "toxiproxy" \
  shopify/toxiproxy:2.1.4
waitforit 1 toxiproxy

# run a one-shot container that sets up the toxiproxy with http calls
docker run \
  --name toxiproxy_cli_ctr \
  --network tough_test_network \
  toxiproxy_cli_img

# run another server 'in front' of toxiproxy, this one will return occasional 503's
# and occasionally abort with no data at all. serves on port 10103 which is bound
# to the host.
docker run -d \
  -p "10103:3000" \
  --name toxy_srv_ctr \
  --network tough_test_network \
  toxy_srv_img:latest
waitforit 1 toxy

echo "**********************************************************************"
echo "the toxic tuf repo is available at http://localhost:10103"

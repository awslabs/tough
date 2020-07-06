#!/usr/bin/env sh
set -eo

# sets up toxiproxy for our test with aborts and timeouts

# create the proxy connection to the tuf fileserver
toxiproxy-cli --host http://toxiproxy:8474 \
  create tuf \
  --listen toxiproxy:5050 \
  --upstream fileserver:10101

# add an abort failure
toxiproxy-cli --host http://toxiproxy:8474 \
  toxic add tuf \
  --toxicName abort \
  --type limit_data \
  --toxicity 0.75 \
  --attribute bytes=500 \
  --downstream

# add a timeout failure (timeout is in milliseconds)
toxiproxy-cli --host http://toxiproxy:8474 \
  toxic add tuf \
  --toxicName timeout \
  --type timeout \
  --toxicity 0.5 \
  --attribute timeout=100 \
  --downstream

# list the setup
toxiproxy-cli --host http://toxiproxy:8474 \
  list

#!/usr/bin/env bash

# sets up toxiproxy for our test with aborts and timeouts

# create the proxy connection to the tuf fileserver
toxiproxy-cli --host http://172.12.13.3:8474 \
    create tuf \
    --listen 172.12.13.3:5050 \
    --upstream 172.12.13.2:10101

# add an abort failure
toxiproxy-cli --host http://172.12.13.3:8474 \
    toxic add tuf \
    --toxicName abort \
    --type limit_data \
    --toxicity 0.75 \
    --attribute bytes=500 \
    --downstream

# add a timeout failure (timeout is in milliseconds)
toxiproxy-cli --host http://172.12.13.3:8474 \
    toxic add tuf \
    --toxicName timeout \
    --type timeout \
    --toxicity 0.5 \
    --attribute timeout=100 \
    --downstream

# list the setup
toxiproxy-cli --host http://172.12.13.3:8474 \
    list

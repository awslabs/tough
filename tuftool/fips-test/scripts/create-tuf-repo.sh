#!/usr/bin/env bash

set -e

ALIAS_SUFFIX=$(date "+%Y-%m-%d")
TEST_TUF_REPO_PATH="./test-tuf-repo"
TEST_KEYS_PATH="test-keys"

tuftool root init --version 1 "${TEST_TUF_REPO_PATH}/1.root.json"

tuftool root gen-rsa-key "${TEST_TUF_REPO_PATH}/1.root.json" "${TEST_KEYS_PATH}/root.pem" --role root

expiration_date=$(date -d "${ALIAS_SUFFIX} + 2 weeks" --iso-8601=date -u)T00:00:00+00:00

tuftool root expire "${TEST_TUF_REPO_PATH}/1.root.json" "${expiration_date}"

tuftool root set-threshold "${TEST_TUF_REPO_PATH}/1.root.json" root 1
tuftool root set-threshold "${TEST_TUF_REPO_PATH}/1.root.json" snapshot 1
tuftool root set-threshold "${TEST_TUF_REPO_PATH}/1.root.json" targets 1
tuftool root set-threshold "${TEST_TUF_REPO_PATH}/1.root.json" timestamp 1

# Add keys                                                                                                                                                                                                                                                     
tuftool root add-key "${TEST_TUF_REPO_PATH}/1.root.json" \
  -k "${TEST_KEYS_PATH}/root.pem" \
  -r root

tuftool root add-key "${TEST_TUF_REPO_PATH}/1.root.json" \
  -k "${TEST_KEYS_PATH}/root.pem" \
   -r snapshot -r targets -r timestamp

tuftool root add-key "${TEST_TUF_REPO_PATH}/1.root.json" \
  -k "${TEST_KEYS_PATH}/root.pem" \
  -r timestamp

# Sign
tuftool root sign "${TEST_TUF_REPO_PATH}/1.root.json" \
  -k "${TEST_KEYS_PATH}/root.pem"

mkdir -p "${TEST_TUF_REPO_PATH}/empty"
tuftool create \
    -t "${TEST_TUF_REPO_PATH}/empty" --outdir "${TEST_TUF_REPO_PATH}/out" --root "${TEST_TUF_REPO_PATH}/1.root.json" \
    -k "${TEST_KEYS_PATH}/root.pem" \
    --snapshot-expires 'in 7 days' --snapshot-version "$(date +%s)" \
    --targets-expires 'in 7 days' --targets-version "$(date +%s)" \
    --timestamp-expires 'in 7 days' --timestamp-version "$(date +%s)"

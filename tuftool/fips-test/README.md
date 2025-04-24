# Testing tough FIPS feature

The following are steps to take to test FIPS support with `tough` and `tuftool`.
Steps will walk through creating a TUF repo, hosting the repo via Docker containers running nginx, and testing `tuftool download` against servers using FIPS and non-FIPS ciphers.
Note that these steps are assumed to be run on Linux.

## Install tuftool

```sh
# From latest release
$ cargo install --force tuftool --all-features
```

```sh
# From local changes
$ cargo install --path ../../tuftool --all-features
```

## Create TUF repo

```sh
$ mkdir -p test-tuf-repo test-keys
$ ./scripts/create-tuf-repo.sh
```

This will create the repo under the "test-tuf-repo" directory and a key for signing the TUF repo under "test-keys".

## Create keys

```sh
$ ./scripts/create-server-keys.sh
```

Trust the generated server Certificate Authority on your host:

```sh
sudo trust anchor --store ./test-keys/ca.crt
```

## Build the tough-fips-testing container

```sh
docker build . -t tough-fips-testing:latest
```

## Run the server with FIPS 

```sh
docker run --rm -p 8080:443 \
  -v ./configs/nginx-fips.conf:/etc/nginx/nginx.conf \
  -v ./test-tuf-repo/out/metadata:/usr/share/nginx/html/metadata \
  -v ./test-tuf-repo/out/targets:/usr/share/nginx/html/targets \
  --mount type=bind,src=./test-keys/server.crt,dst=/etc/pki/tls/certs/domain.crt \
  --mount type=bind,src=./test-keys/server.key,dst=/etc/pki/tls/private/domain.key \
  -d --name "tuf-repo-fips" \
  tough-fips-testing:latest
```

Test repo download:

```sh
tuftool download -r ./test-tuf-repo/1.root.json \
  --targets-url https://localhost:8080/targets  \
  --metadata-url https://localhost:8080/metadata \
  test-fips-tough
```

Should succeed with:

```
Downloading targets to "test-fips-tough"
```

Clean up the downloaded repo:

```sh
rm -rf test-fips-tough/
```

Stop the container:

```
docker stop tuf-repo-fips
```

## Run the server with non-FIPS ciphers

```sh
docker run --rm -p 8080:443 \
  -v ./configs/nginx.conf:/etc/nginx/nginx.conf \
  -v ./test-tuf-repo/out/metadata:/usr/share/nginx/html/metadata \
  -v ./test-tuf-repo/out/targets:/usr/share/nginx/html/targets \
  --mount type=bind,src=./test-keys/server.crt,dst=/etc/pki/tls/certs/domain.crt \
  --mount type=bind,src=./test-keys/server.key,dst=/etc/pki/tls/private/domain.key \
  -d --name "tuf-repo" \
  tough-fips-testing:latest
```

Test repo download:

```sh
tuftool download -r ./test-tuf-repo/1.root.json \
  --targets-url https://localhost:8080/targets  \
  --metadata-url https://localhost:8080/metadata \
  test-fips-tough
```

Expect failure:

```
Failed to load repository: Failed to fetch https://localhost:8080/metadata/2.root.json: Transport 'other' error fetching 'https://localhost:8080/metadata/2.root.json': error sending request for url (https://localhost:8080/metadata/2.root.json)
```

Stop the container:

```
docker stop tuf-repo
```

# Clean up

```
rm -rf test-tuf-repo/
rm -rf test-keys/
rm -rf test-fips-tough/
```

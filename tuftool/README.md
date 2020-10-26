**tuftool** is a Rust command-line utility for generating and signing TUF repositories.

## Installing

To install the latest version of `tuftool`:

```sh
cargo install --force tuftool
```

By default, cargo installs binaries to `~/.cargo/bin`, so you will need this in your path. See the [cargo book](https://doc.rust-lang.org/cargo/commands/cargo-install.html) for more about installing Rust binary crates.

## Minimal TUF Repo

The following is an example of how you can create and download a TUF repository using `tuftool`.
First, create a working directory:

```sh
export WRK="${HOME}/tuftool-example"
mkdir -p "${WRK}"
```

### Create a root.json and Signing Key

For production you may want to use a service like AWS KMS, but for this example we will create keys locally as files:

```sh
# we will store our root.json in $WRK/root
mkdir "${WRK}/root"
# save the path to the root.json we are about to create, we will use it a lot
export ROOT="${WRK}/root/root.json"

# we will store our signing keys in $WRK/keys
mkdir "${WRK}/keys"

# instantiate a new root.json
tuftool root init "${ROOT}"

# set the root file's expiration date
tuftool root expire "${ROOT}" 'in 6 weeks'

# set the signing threshold for each of the standard signing roles. we are saying
# that each of the following roles must have at least 1 valid signature
tuftool root set-threshold "${ROOT}" root 1
tuftool root set-threshold "${ROOT}" snapshot 1
tuftool root set-threshold "${ROOT}" targets 1
tuftool root set-threshold "${ROOT}" timestamp 1

# create an RSA key and store it as a file. this requires openssl on your system
# this command both creates the key and adds it to root.json for the root role
tuftool root gen-rsa-key "${ROOT}" "${WRK}/keys/root.pem" --role root

# for this example we will re-use the same key for the other standard roles
tuftool root add-key "${ROOT}" "${WRK}/keys/root.pem" --role snapshot
tuftool root add-key "${ROOT}" "${WRK}/keys/root.pem" --role targets
tuftool root add-key "${ROOT}" "${WRK}/keys/root.pem" --role timestamp

# sign root.json
tuftool root sign "${ROOT}" -k "${WRK}/keys/root.pem"
```

### Create a new TUF Repo

Now that we have a root.json file, we can create and sign a TUF repository.

```sh
# create a directory to hold the targets that we will sign. we call this the
# 'input' directory because these are the targets that we want to put into
# our TUF repo
mkdir -p "${WRK}/input"

# create the targets that we want in our TUF repo
echo "1" > "${WRK}/input/1.txt"
echo "2" > "${WRK}/input/2.txt"

# create a tuf repo!
tuftool create \
  --root "${ROOT}" \
  --key "${WRK}/keys/root.pem" \
  --add-targets "${WRK}/input" \
  --targets-expires 'in 3 weeks' \
  --targets-version 1 \
  --snapshot-expires 'in 3 weeks' \
  --snapshot-version 1 \
  --timestamp-expires 'in 1 week' \
  --timestamp-version 1 \
  --outdir "${WRK}/tuf-repo"

# you can see our signed repository's metadata here:
ls "${WRK}/tuf-repo/metadata"
# and you can see our signed repository's targets here:
ls "${WRK}/tuf-repo/targets"

### Update TUF Repo

# Change one of the target files
echo "1.1" > "${WRK}/input/1.txt"

# update tuf repo!
tuftool update \
   --root "${ROOT}" \
   --key "${WRK}/keys/root.pem" \
   --add-targets  "${WRK}/input" \
   --targets-expires 'in 3 weeks' \
   --targets-version 2 \
   --snapshot-expires 'in 3 weeks' \
   --snapshot-version 2 \
   --timestamp-expires 'in 1 week' \
   --timestamp-version 2 \
   --outdir "${WRK}/tuf-repo" \
   --metadata-url file:///$WRK/tuf-repo/metadata
```

### Download TUF Repo
Now that we have created TUF repo, we can inspect it using download command. 
Download command is usually used to download a remote repo using HTTP/S url, but 
for this example we will use a file based url to download from local repo.

```sh
# downlaod tuf repo
tuftool download \
   --root "${ROOT}" \
   -t "file://${WRK}/tuf-repo/targets" \
   -m "file://${WRK}/tuf-repo/metadata" \
   "${WRK}/tuf-downlaod"
```

## Testing

Unit tests are run in the usual manner: `cargo test`.
Integration tests require working AWS credentials and are disabled by default behind a feature named `integ`.
To run all tests, including integration tests: `cargo test --features 'integ'` or `AWS_PROFILE=test-profile cargo test --features 'integ'` with specific profile.

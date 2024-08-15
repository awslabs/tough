# Use directory-local cargo root to install version-specific executables into.
export CARGO_HOME = $(shell pwd)/.cargo

# the series of builds, tests and checks that runs for pull requests.
.PHONY: ci
ci: check-licenses build integ

# installs cargo-deny
.PHONY: cargo-deny
cargo-deny:
	cargo install --version 0.14.24 cargo-deny --locked

# checks each crate, and evaluates licenses. requires cargo-deny.
.PHONY: check-licenses
check-licenses: cargo-deny
	cargo deny --all-features check --disable-fetch licenses bans sources

# builds each crate, runs unit tests at the workspace level, and runs linting tools.
.PHONY: build
build:
	set +e
	cargo fmt -- --check
	cargo clippy --locked -- -D warnings
	cargo build --locked -p olpc-cjson
	cargo build --locked -p tough
	cargo build --locked -p tough-ssm
	cargo build --locked -p tough-kms
	cargo build --locked -p tuftool
	cargo test --locked


# installs noxious-server
# We currently build from a forked version, until such a point that the following are resolved:
# https://github.com/oguzbilgener/noxious/issues/13
# https://github.com/oguzbilgener/noxious/pull/14
.PHONY: noxious
noxious:
	cargo install --locked --git https://github.com/cbgbt/noxious.git --tag v1.0.5

# checks tough tests with and without the http feature. http testing requires noxious-server.
.PHONY: integ
integ: noxious
	set +e
	cargo test --manifest-path tough/Cargo.toml --features '' --locked
	cargo test --manifest-path tough/Cargo.toml --all-features --locked

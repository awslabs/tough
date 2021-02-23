# the series of builds, tests and checks that runs for pull requests. requires docker.
.PHONY: ci
ci: build integ

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

# checks tough tests with and without the http feature. http testing requires docker.
.PHONY: integ
integ:
	set +e
	cd tough && cargo test --features '' --locked
	cd tough && cargo test --all-features --locked

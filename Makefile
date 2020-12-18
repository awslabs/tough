.PHONY: ci
ci: ## The series of builds, tests and checks that runs for pull requests. Requires docker.
	set +e
	cargo fmt -- --check
	cargo clippy --locked -- -D warnings
	cargo build --locked -p olpc-cjson
	cargo build --locked -p tough
	cargo build --locked -p tough-ssm
	cargo build --locked -p tough-kms
	cargo build --locked -p tuftool
	cargo test --locked
	cd tough && cargo test --features '' --locked
	cd tough && cargo test --all-features --locked

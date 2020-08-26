**tuftool** is a Rust command-line utility for generating and signing TUF repositories.


## Testing

Unit tests are run in the usual manner: `cargo test`.
Integration tests require working AWS credentials and are disabled by default behind a feature named `integ`.
To run all tests, including integration tests: `cargo test --features 'integ'` or `AWS_PROFILE=test-profile cargo test --features 'integ'` with specific profile.

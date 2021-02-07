# tough

**tough** is a Rust client library for [The Update Framework](https://theupdateframework.github.io/) (TUF) repositories.

**tuftool** is a Rust command-line utility for generating and signing TUF repositories.

## Integration Testing
Integration tests require `docker`.

### Windows❗ Warnings
- Tests can break on Windows if Git's `autocrlf` feature changes line endings.
  This is due to the fact that some tests require files to have a *precise* byte size and hash signature.
  *We have mitigated this with a `.gitattributes` file in the test data directory*.

- Cygwin **must** be installed at `C:\cygwin64\` and have the `make` package installed for integration tests to work properly. 

## Documentation
See [tough - Rust](https://docs.rs/tough/) for the latest `tough` library documentation.

See `tuftool`'s [README](tuftool/README.md) for more on how to use `tuftool`.

## License

tough is licensed under the [Apache License, Version 2.0](LICENSE-APACHE) or the [MIT license](LICENSE-MIT), at your option.

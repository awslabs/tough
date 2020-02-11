# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Added the `refresh` command for refreshing metadata files.

### Changed
- `tuftool create` always copies files instead of (by default) making incorrect symlinks.

### Removed
- Removed the `--copy` and `--hardlink` options to `tuftool create`; `--copy` is now the normal behavior.

## [0.2.0] - 2019-12-16
### Added
- Added integration test `create_verify_repo`, which creates a TUF repo with `tuftool` and verifies we can read its targets with `tough`.

### Changed
- Updated tough to v0.3
- Changed `RootKeys` to be a `HashMap<Decoded<Hex>, Box<dyn Sign>>` to remove a reference to `KeyPair` (see "Removed" section)
- `KeySource` now contains an `as_sign` method that returns `Result<Box<dyn Sign>>`.

### Removed
- Remove `KeyPair` enum from `tuftool` and updated any areas that reference this enum.
- Remove `KeySource::as_keypair` method.

## [0.1.1] - 2019-12-04
### Changed
- Updated tough to v0.2.
- Updated pem to v0.7.
- Updated rusoto to v0.42.
- Updated snafu to v0.6.
- Switched to using `ring::digest` for SHA-256 digest calculation.
- Replaced a use of the deprecated tempdir crate with tempfile.

## [0.1.0] - 2019-11-08
### Added
- Everything!

[Unreleased]: https://github.com/awslabs/tough/compare/tuftool-v0.2.0...HEAD
[0.2.0]: https://github.com/awslabs/tough/compare/tuftool-v0.1.1...tuftool-v0.2.0
[0.1.1]: https://github.com/awslabs/tough/compare/tuftool-v0.1.0...tuftool-v0.1.1
[0.1.0]: https://github.com/awslabs/tough/releases/tag/tuftool-v0.1.0

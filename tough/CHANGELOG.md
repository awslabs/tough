# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Updated `reqwest` to `0.10.1` to fix an issue with https failures. Note this requires use of `reqwest::blocking::*` instead of `reqwest::*` in code that is using HttpTransport.
- Update all dependencies with `cargo update`.

## [0.3.0] - 2019-12-16
### Added
- Added the `Sign` trait to `tough`, which allows users to sign data.
- Added the `canonical_form` method to the `Role` trait, which serializes the role into canonical JSON.

## [0.2.0] - 2019-12-04
### Added
- New methods `root`, `snapshot`, and `timestamp` on `Repository` to access the signed roles.

### Changed
- Changed the return type of `Repository::targets` to the signed role (`Signed<Targets>`). The top-level `Target` type is no longer necessary. **This is a breaking change.**
- Updated snafu to v0.6. **This is a breaking change** to the `snafu::ErrorCompat` implementation on library error types.
- Updated pem to v0.7.
- Switched to using `ring::digest` for SHA-256 digest calculation.
- Added `Debug`, `Clone`, and `Copy` implementations to structs when appropriate.

## [0.1.0] - 2019-11-08
### Added
- Everything!

[Unreleased]: https://github.com/awslabs/tough/compare/tuftool-v0.3.0...HEAD
[0.3.0]: https://github.com/awslabs/tough/compare/tough-v0.2.0...tough-v0.3.0
[0.2.0]: https://github.com/awslabs/tough/compare/tough-v0.1.0...tough-v0.2.0
[0.1.0]: https://github.com/awslabs/tough/releases/tag/tough-v0.1.0

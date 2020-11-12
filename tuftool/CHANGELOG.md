# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Support `file://` URLs with the download command [#222]
- Support download and update of expired repos [#224]
- Set version command for specifying the `root.json` version. [#236]

### Changed
- `tough-kms` fix to prevent occasional bad repo signing with KMS [#263]
- Other dependency updates.

[#222]: https://github.com/awslabs/tough/pull/222
[#224]: https://github.com/awslabs/tough/pull/224
[#236]: https://github.com/awslabs/tough/pull/236
[#263]: https://github.com/awslabs/tough/issues/263

## [0.5.0] - 2020-09-14
### Added
- Added delegated targets
- Added support for cross-signing a new root from an old root
- Added support for AWS KMS asymmetric keys (using tough-kms)

## [0.4.1] - 2020-07-20
### Added
- Added logging.
- Added downloading of specific targets.
- Allow control of link/copy behavior for existing paths.

### Changed
- Bumped `tough` to 0.8.0.
- Bumped `tough-ssm` to 0.2.1.
- Truncate targets that already exist before downloading with `tuftool`.

## [0.4.0] - 2020-06-11

Major update: much of the logic in `tuftool` has been factored out and added to `tough`

### Added
- Added `tuftool update`, which allows a user to update an existing repository's metadata and optionally add targets. (This addition deprecates `tuftool refresh`; see note below)
- `tuftool download` now creates its output directory.

### Removed
- Removed `tuftool refresh` in favor of the new `tuftool update` command
- Lots of under-the-hood business logic, which is mostly invisible to the user. :)

### Changed
- `tuftool create`'s interface now uses flags rather than positional arguments to better align with `tuftool update`
- Dependency updates.

## [0.3.1] - (Unreleased)
### Added
- Accommodate `tough`'s change from `target_base_url` to `targets_base_url`.

## [0.3.0] - 2020-02-11
### Added
- Added the `refresh` command for refreshing metadata files.

### Changed
- `tuftool create` always copies files instead of (by default) making incorrect symlinks.
- Renamed the `indir` argument of the `download` command to `outdir` to reflect its purpose correctly.

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

[Unreleased]: https://github.com/awslabs/tough/compare/tuftool-v0.5.0...develop
[0.5.0]: https://github.com/awslabs/tough/compare/tuftool-v0.4.1...tuftool-v0.5.0
[0.4.1]: https://github.com/awslabs/tough/compare/tuftool-v0.4.0...tuftool-v0.4.1
[0.4.0]: https://github.com/awslabs/tough/compare/tuftool-v0.3.1...tuftool-v0.4.0
[0.3.1]: https://github.com/awslabs/tough/compare/tuftool-v0.3.0...tuftool-v0.3.1
[0.3.0]: https://github.com/awslabs/tough/compare/tuftool-v0.2.0...tuftool-v0.3.0
[0.2.0]: https://github.com/awslabs/tough/compare/tuftool-v0.1.1...tuftool-v0.2.0
[0.1.1]: https://github.com/awslabs/tough/compare/tuftool-v0.1.0...tuftool-v0.1.1
[0.1.0]: https://github.com/awslabs/tough/releases/tag/tuftool-v0.1.0

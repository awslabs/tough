# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.3] - 2021-08-24
### Changes
- Update `assert_cmd` dependency.  [#402]
- Add `clone` subcommand.  [#404]

[#402]: https://github.com/awslabs/tough/pull/402
[#404]: https://github.com/awslabs/tough/pull/404

## [0.6.2] - 2021-07-30
### Changes
- Update dependencies.  [#363], [#364], [#365], [#366], [#367], [#379], [#381], [#382], [#384], [#391], [#393], [#396], [#398]
- Fix clippy warnings.  [#372], [#378], [#383], [#399]
- Add license check to CI.  [#385]

[#363]: https://github.com/awslabs/tough/pull/363
[#364]: https://github.com/awslabs/tough/pull/364
[#365]: https://github.com/awslabs/tough/pull/365
[#366]: https://github.com/awslabs/tough/pull/366
[#367]: https://github.com/awslabs/tough/pull/367
[#372]: https://github.com/awslabs/tough/pull/372
[#378]: https://github.com/awslabs/tough/pull/378
[#379]: https://github.com/awslabs/tough/pull/379
[#381]: https://github.com/awslabs/tough/pull/381
[#382]: https://github.com/awslabs/tough/pull/382
[#383]: https://github.com/awslabs/tough/pull/383
[#384]: https://github.com/awslabs/tough/pull/384
[#385]: https://github.com/awslabs/tough/pull/385
[#391]: https://github.com/awslabs/tough/pull/391
[#393]: https://github.com/awslabs/tough/pull/393
[#396]: https://github.com/awslabs/tough/pull/396
[#398]: https://github.com/awslabs/tough/pull/398
[#399]: https://github.com/awslabs/tough/pull/399

## [0.6.1] - 2021-03-01
### Changed
- Update various dependencies to use tokio v1. [#330]

[#330]: https://github.com/awslabs/tough/pull/330

## [0.6.0] - 2021-01-19
### Breaking Changes
- Correct spelling of `tuftool download` argument from `--target-url` to `--targets-url` [#309]

### Added
- Support `file://` URLs with the download command [#222]
- Support download and update of expired repos [#224]
- Set version command for specifying the `root.json` version. [#236]

### Changed
- Updated `tough` dependency to 0.10.0.
- Updated `tough-kms` dependency to 0.2.0 (which includes fix for [#263]).
- Updated `tough-ssm` to 0.5.0. 
- Other dependency updates.

[#222]: https://github.com/awslabs/tough/pull/222
[#224]: https://github.com/awslabs/tough/pull/224
[#236]: https://github.com/awslabs/tough/pull/236
[#263]: https://github.com/awslabs/tough/issues/263
[#309]: https://github.com/awslabs/tough/pull/309

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

[Unreleased]: https://github.com/awslabs/tough/compare/tuftool-v0.6.3...develop
[0.6.3]: https://github.com/awslabs/tough/compare/tuftool-v0.6.2...tuftool-v0.6.3
[0.6.2]: https://github.com/awslabs/tough/compare/tuftool-v0.6.1...tuftool-v0.6.2
[0.6.1]: https://github.com/awslabs/tough/compare/tuftool-v0.6.0...tuftool-v0.6.1
[0.6.0]: https://github.com/awslabs/tough/compare/tuftool-v0.5.0...tuftool-v0.6.0
[0.5.0]: https://github.com/awslabs/tough/compare/tuftool-v0.4.1...tuftool-v0.5.0
[0.4.1]: https://github.com/awslabs/tough/compare/tuftool-v0.4.0...tuftool-v0.4.1
[0.4.0]: https://github.com/awslabs/tough/compare/tuftool-v0.3.1...tuftool-v0.4.0
[0.3.1]: https://github.com/awslabs/tough/compare/tuftool-v0.3.0...tuftool-v0.3.1
[0.3.0]: https://github.com/awslabs/tough/compare/tuftool-v0.2.0...tuftool-v0.3.0
[0.2.0]: https://github.com/awslabs/tough/compare/tuftool-v0.1.1...tuftool-v0.2.0
[0.1.1]: https://github.com/awslabs/tough/compare/tuftool-v0.1.0...tuftool-v0.1.1
[0.1.0]: https://github.com/awslabs/tough/releases/tag/tuftool-v0.1.0

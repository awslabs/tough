# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2023-12-05

### Changes
- Dependency updates

## [0.7.0] - 2023-11-07

### Changes
- ❗Breaking Change❗: The `KeySource` and `Sign` traits are now async [#687]
- Expand AWS credential file support, e.g. enable `source_profile` and `credential_process` [#670]

[#670]: https://github.com/awslabs/tough/pull/670
[#687]: https://github.com/awslabs/tough/pull/687

## [0.6.0] - 2023-08-22
### Changes
- Bump AWS SDK for Rust [#610]
- Other dependency updates

[#610]: https://github.com/awslabs/tough/pull/610

## [0.5.0] - 2023-03-02
### Changes
- Replaced a deprecated function (aws_sdk_kms::Client::from_conf_conn) [#568]
- Remove minor/patch versions from Cargo.tomls [#573]
- Bump tokio from ~1.18 (LTS) to 1.25.0 [#555], [#568]
- Update dependencies

[#555]: https://github.com/awslabs/tough/pull/555
[#568]: https://github.com/awslabs/tough/pull/568
[#573]: https://github.com/awslabs/tough/pull/573

## [0.4.2] - 2022-10-03
### Changes
- Update dependencies [#501], [#502], [#514]

[#501]: https://github.com/awslabs/tough/pull/501
[#502]: https://github.com/awslabs/tough/pull/502
[#514]: https://github.com/awslabs/tough/pull/514

## [0.4.1] - 2022-08-12
### Changes
- Update dependencies

## [0.4.0] - 2022-07-26
### Breaking Changes
- Replaced `rusoto` with `aws-sdk-rust` [#469]
- Update dependencies

[#469]: https://github.com/awslabs/tough/pull/469

## [0.3.6] - 2022-04-26
### Changes
- Do not pin tokio version in Cargo.toml. [#451]
- Fix clippy warnings. [#455]
- Update dependencies.

[#451]: https://github.com/awslabs/tough/pull/451
[#455]: https://github.com/awslabs/tough/pull/455

## [0.3.5] - 2022-01-28
### Changes
- Update dependencies.

## [0.3.4] - 2021-10-19
### Changes
- Update dependencies.

## [0.3.3] - 2021-09-15
### Changes
- Update dependencies.

## [0.3.2] - 2021-08-24
### Changes
- Update `tough` dependency to 0.11.2

## [0.3.1] - 2021-07-30
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

## [0.3.0] - 2021-03-01
### Breaking Changes
- Update `tokio` to v1. [#330]
- Update `rusoto` to 0.46. [#330]
- Update `tough` to 0.11.0.

[#330]: https://github.com/awslabs/tough/pull/330

## [0.2.0] - 2021-01-19
### Changes
- Update `tough` dependency to 0.10.0.

## [0.1.1] - 2020-11-10
### Changes
- We now pad signatures shorter than the RSA modulus to ensure compatibility with other implementations of RSA PSS ([#263]).
- Update `rusoto` dependency to 0.45.0.

[#263]: https://github.com/awslabs/tough/pull/263

## [0.1.0] - 2020-09-17
### Added
- Everything!

[Unreleased]: https://github.com/awslabs/tough/compare/tough-kms-v0.8.0...develop
[0.8.0]: https://github.com/awslabs/tough/compare/tough-kms-v0.7.0...tough-kms-v0.8.0
[0.7.0]: https://github.com/awslabs/tough/compare/tough-kms-v0.6.0...tough-kms-v0.7.0
[0.6.0]: https://github.com/awslabs/tough/compare/tough-kms-v0.5.0...tough-kms-v0.6.0
[0.5.0]: https://github.com/awslabs/tough/compare/tough-kms-v0.4.2...tough-kms-v0.5.0
[0.4.2]: https://github.com/awslabs/tough/compare/tough-kms-v0.4.1...tough-kms-v0.4.2
[0.4.1]: https://github.com/awslabs/tough/compare/tough-kms-v0.4.0...tough-kms-v0.4.1
[0.4.0]: https://github.com/awslabs/tough/compare/tough-kms-v0.3.6...tough-kms-v0.4.0
[0.3.6]: https://github.com/awslabs/tough/compare/tough-kms-v0.3.5...tough-kms-v0.3.6
[0.3.5]: https://github.com/awslabs/tough/compare/tough-kms-v0.3.4...tough-kms-v0.3.5
[0.3.4]: https://github.com/awslabs/tough/compare/tough-kms-v0.3.3...tough-kms-v0.3.4
[0.3.3]: https://github.com/awslabs/tough/compare/tough-kms-v0.3.2...tough-kms-v0.3.3
[0.3.2]: https://github.com/awslabs/tough/compare/tough-kms-v0.3.1...tough-kms-v0.3.2
[0.3.1]: https://github.com/awslabs/tough/compare/tough-kms-v0.3.0...tough-kms-v0.3.1
[0.3.0]: https://github.com/awslabs/tough/compare/tough-kms-v0.2.0...tough-kms-v0.3.0
[0.2.0]: https://github.com/awslabs/tough/compare/tough-kms-v0.1.1...tough-kms-v0.2.0
[0.1.1]: https://github.com/awslabs/tough/compare/tough-kms-v0.1.0...tough-kms-v0.1.1
[0.1.0]: https://github.com/awslabs/tough/releases/tag/tough-kms-v0.1.0

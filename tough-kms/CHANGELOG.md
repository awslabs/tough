# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.3.0]: https://github.com/awslabs/tough/compare/tough-kms-v0.2.0...tough-kms-v0.3.0
[0.2.0]: https://github.com/awslabs/tough/compare/tough-kms-v0.1.1...tough-kms-v0.2.0
[0.1.1]: https://github.com/awslabs/tough/compare/tough-kms-v0.1.0...tough-kms-v0.1.1
[0.1.0]: https://github.com/awslabs/tough/releases/tag/tough-kms-v0.1.0

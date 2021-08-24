# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.3.2]: https://github.com/awslabs/tough/compare/tough-kms-v0.3.1...tough-kms-v0.3.2
[0.3.1]: https://github.com/awslabs/tough/compare/tough-kms-v0.3.0...tough-kms-v0.3.1
[0.3.0]: https://github.com/awslabs/tough/compare/tough-kms-v0.2.0...tough-kms-v0.3.0
[0.2.0]: https://github.com/awslabs/tough/compare/tough-kms-v0.1.1...tough-kms-v0.2.0
[0.1.1]: https://github.com/awslabs/tough/compare/tough-kms-v0.1.0...tough-kms-v0.1.1
[0.1.0]: https://github.com/awslabs/tough/releases/tag/tough-kms-v0.1.0

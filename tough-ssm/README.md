tough-ssm implements the `KeySource` trait found in [tough, a Rust TUF client](https://github.com/awslabs/tough).
By implementing this trait, AWS SSM can become a source of keys used to sign a [TUF repository](https://theupdateframework.github.io/).

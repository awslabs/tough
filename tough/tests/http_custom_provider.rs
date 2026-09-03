#![cfg(all(feature = "http-custom-provider", not(feature = "http")))]

use rustls::crypto::{aws_lc_rs, CryptoProvider};
use tough::HttpTransportBuilder;

#[test]
fn custom_provider_builder_does_not_install_a_process_default() {
    assert!(CryptoProvider::get_default().is_none());

    let _transport = HttpTransportBuilder::new()
        .crypto_provider(aws_lc_rs::default_provider())
        .build();

    assert!(CryptoProvider::get_default().is_none());
}

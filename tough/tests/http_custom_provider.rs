#![cfg(all(feature = "http-custom-provider", not(feature = "http")))]

use rustls::crypto::{ring, CryptoProvider};
use tough::HttpTransportBuilder;

#[test]
fn custom_provider_builder_does_not_install_a_process_default() {
    assert!(CryptoProvider::get_default().is_none());

    let _transport = HttpTransportBuilder::new()
        .crypto_provider(ring::default_provider())
        .build();

    assert!(CryptoProvider::get_default().is_none());
}

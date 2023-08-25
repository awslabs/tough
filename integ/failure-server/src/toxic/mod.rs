use anyhow::{Context, Result};
use std::fmt::Debug;
use std::net::{SocketAddr, ToSocketAddrs};

pub(crate) use http_server::ToxicStaticHttpServer;
pub(crate) use tcp_proxy::ToxicTcpProxy;

mod http_server;
mod tcp_proxy;

/// Attempts to read exactly one `SocketAddr` from a `ToSocketAddrs`.
///
/// Returns an error if more than one SocketAddr is present.
trait ToSocketAddrsExt {
    fn parse_only_one_address(self) -> Result<SocketAddr>;
}

impl<T: ToSocketAddrs + Debug> ToSocketAddrsExt for T {
    fn parse_only_one_address(self) -> Result<SocketAddr> {
        let mut addresses = self
            .to_socket_addrs()
            .context(format!("Failed to parse {self:?} as socket address"))?;

        let address = addresses
            .next()
            .context(format!("Did not parse any addresses from {self:?}"))?;

        anyhow::ensure!(
            addresses.next().is_none(),
            format!("Listen address ({:?}) must parse to one address.", address)
        );

        Ok(address)
    }
}

//! Wrapper around running [`noxious-server`](https://github.com/oguzbilgener/noxious)
//!
//! `noxious-server` is a TCP proxy that introduces chaos at the TCP layer.
use super::ToSocketAddrsExt;
use anyhow::{Context, Result};
use noxious_client::{Client, Toxic};
use std::net::ToSocketAddrs;
use std::process::Command;
use std::{fmt::Debug, net::SocketAddr};
use tempfile::NamedTempFile;
use tokio_retry::{strategy::ExponentialBackoff, Retry};

/// A TCP proxy server that introduces artificial faults at the TCP layer.
#[derive(Debug)]
pub(crate) struct ToxicTcpProxy {
    /// The name of the noxious proxy. Written to `ProxyConfig`.
    name: String,
    /// The proxy's listen address. Written to `ProxyConfig`.
    listen: SocketAddr,
    /// The upstream's listen address. Written to `ProxyConfig`.
    upstream: SocketAddr,
    /// The proxy's control API address.
    api_listen: SocketAddr,
    /// The running server process.
    running_server: Option<std::process::Child>,
    /// The list of toxics to apply to connections.
    toxics: Vec<Toxic>,
}

fn retry_strategy() -> impl Iterator<Item = std::time::Duration> {
    ExponentialBackoff::from_millis(500).take(10)
}

impl ToxicTcpProxy {
    pub(crate) fn new<T1, T2, T3>(
        name: String,
        listen: T1,
        upstream: T2,
        api_listen: T3,
    ) -> Result<Self>
    where
        T1: ToSocketAddrs + Debug,
        T2: ToSocketAddrs + Debug,
        T3: ToSocketAddrs + Debug,
    {
        let listen = listen.parse_only_one_address()?;
        let upstream = upstream.parse_only_one_address()?;
        let api_listen = api_listen.parse_only_one_address()?;
        let running_server = None;
        let toxics = Vec::new();

        Ok(Self {
            name,
            listen,
            upstream,
            api_listen,
            running_server,
            toxics,
        })
    }

    pub(crate) fn with_toxic(mut self, toxic: Toxic) -> Self {
        self.toxics.push(toxic);
        self
    }

    /// Starts the noxious-server.
    ///
    /// If the server is already running, it will be restarted.
    pub(crate) async fn start(&mut self) -> Result<()> {
        // Stop any existing server
        self.stop().ok();

        // Configure and start the server
        let proxy_config = serde_json::json!([{
            "name": &self.name,
            "listen": self.listen.to_string(),
            "upstream": self.upstream.to_string(),
        }]);

        let config_tmpfile =
            NamedTempFile::new().context("Failed to create tmpfile for noxious proxy config")?;
        serde_json::to_writer(&config_tmpfile, &proxy_config)
            .context("Failed to write proxy config file for noxious")?;

        #[rustfmt::skip]
        let noxious_process = Command::new("noxious-server")
            .args([
                "--config", &config_tmpfile.path().to_string_lossy(),
                "--host", &self.api_listen.ip().to_string(),
                "--port", &self.api_listen.port().to_string(),
            ])
            .spawn()
            .context("Failed to start noxious server")?;

        self.running_server = Some(noxious_process);

        // Configure toxics
        let client = Client::new(&self.api_listen.to_string());
        let proxy = Retry::spawn(retry_strategy(), || async {
            client.proxy(&self.name).await.context(format!(
                "Failed to find our configured proxy '{}'",
                self.name
            ))
        })
        .await?;
        for toxic in &self.toxics {
            Retry::spawn(retry_strategy(), || async {
                proxy.add_toxic(toxic).await.context(format!(
                    "Failed to apply toxic {:?} to proxy '{}'",
                    toxic, self.name
                ))
            })
            .await?;
        }

        Ok(())
    }

    /// Attempts to kill the running server, if there is one.
    ///
    /// Succeeds if the server is killed successfully or if it isn't/was never running.
    pub(crate) fn stop(&mut self) -> Result<()> {
        self.running_server
            .as_mut()
            .map(std::process::Child::kill)
            .transpose()
            .context("Failed to kill noxious server.")?;
        self.running_server = None;
        Ok(())
    }
}

impl Drop for ToxicTcpProxy {
    fn drop(&mut self) {
        self.stop().ok();
    }
}

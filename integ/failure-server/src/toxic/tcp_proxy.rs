//! In-process TCP chaos proxy built on [`tokio-netem`].
//!
//! Accepts connections on `listen`, opens an upstream TCP connection to `upstream`, and copies
//! bytes bidirectionally. The downstream (server -> client) half of each connection is wrapped
//! with fault-injection adapters that reproduce the behavior of the two `noxious` toxics that
//! used to live here:
//!
//! * `Terminator` at probability [`FaultConfig::terminate_probability`] — every poll on the
//!   downstream write half has that chance to permanently fail the connection, similar to the
//!   old `Timeout` toxic (which stalled forever; here the client sees an error instead of a hang,
//!   which the caller's HTTP retry loop still recovers from).
//! * `Shutdowner` fired after [`FaultConfig::slow_close_delay`] with probability
//!   [`FaultConfig::slow_close_probability`] — mirrors the old `SlowClose` toxic that closed the
//!   connection some milliseconds into its life.
//!
//! No external binary is required.
use super::ToSocketAddrsExt;
use anyhow::{Context, Result};
use std::fmt::Debug;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_netem::shutdowner::Shutdowner;
use tokio_netem::terminator::Terminator;

/// Fault-injection knobs for [`ToxicTcpProxy`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct FaultConfig {
    /// Per-poll probability that the downstream write half is terminated with an error.
    /// Replaces the noxious `Timeout` toxic (`toxicity = 0.5`).
    pub(crate) terminate_probability: f64,
    /// Probability that a scheduled slow-close is armed for a given connection.
    /// Replaces the noxious `SlowClose` toxic (`toxicity = 0.75`).
    pub(crate) slow_close_probability: f64,
    /// Delay after which an armed slow-close fires and shuts the downstream half with an error.
    /// Replaces the noxious `SlowClose` `delay: 500` ms.
    pub(crate) slow_close_delay: Duration,
}

/// A TCP proxy that introduces artificial faults on the downstream half of each connection.
#[derive(Debug)]
pub(crate) struct ToxicTcpProxy {
    listen: SocketAddr,
    upstream: SocketAddr,
    fault_config: FaultConfig,
    running_server: Option<JoinHandle<Result<()>>>,
}

impl ToxicTcpProxy {
    pub(crate) fn new<T1, T2>(listen: T1, upstream: T2, fault_config: FaultConfig) -> Result<Self>
    where
        T1: ToSocketAddrs + Debug,
        T2: ToSocketAddrs + Debug,
    {
        let listen = listen.parse_only_one_address()?;
        let upstream = upstream.parse_only_one_address()?;
        Ok(Self {
            listen,
            upstream,
            fault_config,
            running_server: None,
        })
    }

    /// Starts the proxy task. If already running, it is restarted.
    pub(crate) async fn start(&mut self) -> Result<()> {
        self.stop().ok();

        let listener = TcpListener::bind(self.listen)
            .await
            .with_context(|| format!("Failed to bind toxic tcp proxy at {}", self.listen))?;
        let upstream = self.upstream;
        let fault_config = self.fault_config;

        self.running_server = Some(tokio::spawn(async move {
            run_proxy(listener, upstream, fault_config).await
        }));

        Ok(())
    }

    /// Stops the running proxy task, if any.
    pub(crate) fn stop(&mut self) -> Result<()> {
        if let Some(handle) = self.running_server.take() {
            handle.abort();
        }
        Ok(())
    }
}

impl Drop for ToxicTcpProxy {
    fn drop(&mut self) {
        self.stop().ok();
    }
}

/// Accept loop: for each inbound connection, dial the upstream and spawn a bidirectional copy
/// with fault-injection adapters wrapped around the downstream half.
async fn run_proxy(
    listener: TcpListener,
    upstream: SocketAddr,
    fault_config: FaultConfig,
) -> Result<()> {
    loop {
        let (client, _peer) = listener
            .accept()
            .await
            .context("toxic tcp proxy: accept failed")?;
        tokio::spawn(async move {
            if let Err(err) = handle_connection(client, upstream, fault_config).await {
                // These are expected during chaos; log at debug level via eprintln (no tracing dep).
                eprintln!("toxic tcp proxy: connection ended: {err:#}");
            }
        });
    }
}

async fn handle_connection(
    client: TcpStream,
    upstream_addr: SocketAddr,
    fault_config: FaultConfig,
) -> Result<()> {
    let upstream = TcpStream::connect(upstream_addr)
        .await
        .with_context(|| format!("toxic tcp proxy: failed to dial upstream {upstream_addr}"))?;

    // Split both sides so we can wrap only the downstream (upstream -> client) direction.
    let (mut client_read, client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    // Optionally arm a slow-close: after `slow_close_delay`, force the downstream half to error.
    // `Shutdowner` takes a `oneshot::Receiver<Box<dyn Error + Send + Sync>>`. Dropping the sender
    // without sending also trips the receiver with a generic shutdown error, so we must keep the
    // sender alive for the lifetime of the connection when we do *not* want to force-close.
    type ShutdownErr = Box<dyn std::error::Error + Send + Sync>;
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<ShutdownErr>();
    let _shutdown_tx_guard = if rand::random::<f64>() < fault_config.slow_close_probability {
        let delay = fault_config.slow_close_delay;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let err: ShutdownErr = Box::new(io::Error::other("toxic tcp proxy: slow-close fired"));
            let _ = shutdown_tx.send(err);
        });
        None
    } else {
        // Hold the sender on the stack; it's dropped only when the connection ends.
        Some(shutdown_tx)
    };

    // Wrap the client-facing write half with Terminator (random per-poll abort) and Shutdowner
    // (external kill switch driven by the slow-close timer).
    let client_write = Terminator::new(client_write, fault_config.terminate_probability);
    let mut client_write = Shutdowner::new(client_write, shutdown_rx);

    // Client -> upstream is unmolested; only the downstream direction is toxic.
    let client_to_upstream = async {
        let n = io::copy(&mut client_read, &mut upstream_write).await?;
        upstream_write.shutdown().await.ok();
        Ok::<u64, io::Error>(n)
    };
    let upstream_to_client = async {
        let n = io::copy(&mut upstream_read, &mut client_write).await?;
        // Best-effort close; may already be broken by the fault adapters.
        let _ = client_write.shutdown().await;
        Ok::<u64, io::Error>(n)
    };

    // `try_join` gives up as soon as either side errors, which is the desired chaos behavior.
    let _ = tokio::try_join!(client_to_upstream, upstream_to_client);
    Ok(())
}

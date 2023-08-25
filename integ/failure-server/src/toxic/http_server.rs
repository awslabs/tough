//! A simple filesystem HTTP server that introduces chaos at the HTTP layer.
//!
//! Chaos includes:
//! * Occasional additional request latency
//! * Occasional 503 responses
use super::ToSocketAddrsExt;
use anyhow::{Context, Result};
use axum::{
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    Router,
};
use std::fmt::Debug;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use tower_fault::latency::LatencyLayer;
use tower_http::services::ServeDir;

const ERR_503_PROBABILITY: f64 = 0.5;
const LATENCY_PROBABILITY: f64 = 0.1;

/// An HTTP server which serves static files from a directory.
///
/// The server implementation is "toxic" in that it introduces artificial faults at the HTTP layer.
#[derive(Debug)]
pub(crate) struct ToxicStaticHttpServer {
    /// The proxy's listen address. Written to `ProxyConfig`.
    listen: SocketAddr,

    /// The path to serve static content from.
    serve_dir: PathBuf,

    /// Running server, if any
    running_server: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl ToxicStaticHttpServer {
    pub(crate) fn new<T, P>(listen: T, serve_dir: P) -> Result<Self>
    where
        T: ToSocketAddrs + Debug,
        P: AsRef<Path>,
    {
        let listen = listen.parse_only_one_address()?;
        let serve_dir = serve_dir.as_ref().to_owned();
        let running_server = None;

        Ok(Self {
            listen,
            serve_dir,
            running_server,
        })
    }

    /// Starts the HTTP server.
    pub(crate) fn start(&mut self) -> Result<()> {
        // Stop any existing server
        self.stop().ok();

        // Chance to inject 50 to 200 milliseconds of latency
        let latency_layer = LatencyLayer::new(LATENCY_PROBABILITY, 50..200);
        // Chance to return an HTTP 503 error
        let error_layer = middleware::from_fn(maybe_return_error);

        let app = Router::new()
            .nest_service("/", ServeDir::new(&self.serve_dir))
            .layer(error_layer)
            .layer(latency_layer);
        let server = axum::Server::bind(&self.listen).serve(app.into_make_service());

        self.running_server = Some(tokio::spawn(async {
            server.await.context("Failed to run ToxicStaticHttpServer")
        }));

        Ok(())
    }

    /// Attempts to kill the running server, if there is one.
    ///
    /// Succeeds if the server is killed successfully or if it isn't/was never running.
    pub(crate) fn stop(&mut self) -> Result<()> {
        if let Some(server) = self.running_server.take() {
            server.abort();
        }
        Ok(())
    }
}

/// Middleware for chaotically returning a 503 error.
async fn maybe_return_error<B>(req: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
    if rand::random::<f64>() < ERR_503_PROBABILITY {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    } else {
        Ok(next.run(req).await)
    }
}

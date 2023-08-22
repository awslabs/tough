//! This module sets up 2 HTTP servers.
//!   * ToxicStaticHttpServer: serves TUF repo files on port 10101, with occasional random 503s.
//!   * ToxicTcpProxy: proxies to the TUF repo on port 10102, with occasional toxic behavior.
use anyhow::Result;
use noxious_client::{StreamDirection, Toxic, ToxicKind};
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;
use toxic::{ToxicStaticHttpServer, ToxicTcpProxy};

mod toxic;

const STATIC_HTTP_SERVER_LISTEN: &str = "127.0.0.1:10101";
const TCP_PROXY_LISTEN: &str = "127.0.0.1:10102";
const TCP_PROXY_CONFIG_API_LISTEN: &str = "127.0.0.1:8472";

pub struct IntegServers {
    toxic_tcp_proxy: ToxicTcpProxy,
    toxic_static_http_server: ToxicStaticHttpServer,
}

impl IntegServers {
    pub fn new<P: AsRef<Path>>(tuf_reference_repo: P) -> Result<Self> {
        let tuf_reference_repo = tuf_reference_repo.as_ref().to_owned();

        let toxic_tcp_proxy = ToxicTcpProxy::new(
            "toxictuf".to_string(),
            TCP_PROXY_LISTEN,
            STATIC_HTTP_SERVER_LISTEN,
            TCP_PROXY_CONFIG_API_LISTEN,
        )?
        .with_toxic(Toxic {
            name: "slowclose".to_string(),
            kind: ToxicKind::SlowClose { delay: 500 },
            toxicity: 0.75,
            direction: StreamDirection::Downstream,
        })
        .with_toxic(Toxic {
            name: "timeout".to_string(),
            kind: ToxicKind::Timeout { timeout: 100 },
            toxicity: 0.5,
            direction: StreamDirection::Downstream,
        });

        let toxic_static_http_server =
            ToxicStaticHttpServer::new(STATIC_HTTP_SERVER_LISTEN, tuf_reference_repo)?;

        Ok(Self {
            toxic_tcp_proxy,
            toxic_static_http_server,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // Make sure we're starting from scratch
        self.teardown()?;

        self.toxic_static_http_server.start()?;
        self.toxic_tcp_proxy.start().await?;
        sleep(Duration::from_secs(1)); // give the servers a chance to start

        println!("**********************************************************************");
        println!("the toxic tuf repo is available at {TCP_PROXY_LISTEN}");

        Ok(())
    }

    pub fn teardown(&mut self) -> Result<()> {
        self.toxic_tcp_proxy.stop()?;
        self.toxic_static_http_server.stop()?;

        Ok(())
    }
}

impl Drop for IntegServers {
    fn drop(&mut self) {
        self.teardown().ok();
    }
}

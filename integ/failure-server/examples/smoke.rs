//! Smoke test for `IntegServers`: verifies the in-process TCP chaos proxy is wired up correctly
//! and that both success and failure paths fire.
//!
//! Usage: `cargo run --example smoke -p failure-server -- <path-to-tuf-repo>`
use failure_server::IntegServers;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let tuf_ref = std::env::args()
        .nth(1)
        .expect("pass a directory path to serve");

    let mut servers = IntegServers::new(&tuf_ref)?;
    servers.run().await?;

    let mut ok = 0usize;
    let mut err = 0usize;

    for i in 0..40 {
        let attempt = async {
            let mut stream = TcpStream::connect("127.0.0.1:10102").await?;
            stream
                .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .await?;
            let mut buf = Vec::new();
            let n = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf))
                .await
                .map_err(|_| anyhow::anyhow!("read timeout"))??;
            Ok::<Vec<u8>, anyhow::Error>(buf[..n].to_vec())
        }
        .await;

        match attempt {
            Ok(bytes) if !bytes.is_empty() => {
                ok += 1;
                println!("[{i}] ok, {} bytes", bytes.len());
            }
            Ok(_) => {
                err += 1;
                println!("[{i}] empty response (chaos)");
            }
            Err(e) => {
                err += 1;
                println!("[{i}] err: {e}");
            }
        }
    }

    println!("summary: ok={ok} err={err}");
    if ok == 0 {
        anyhow::bail!("no successful fetches — chaos too aggressive or upstream broken");
    }
    if err == 0 {
        anyhow::bail!("no failed fetches — chaos not firing");
    }
    Ok(())
}

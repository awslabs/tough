/// This module is for code that is re-used by different `tuftool` subcommands.
use crate::error::{self, Result};
use snafu::ResultExt;
use tough::{Repository, RepositoryLoader};
use url::Url;

#[cfg(feature = "s3")]
use tough_s3::S3Transport;

/// Some commands only deal with metadata and never use a targets directory.
/// When loading a repo that does not need a targets directory, we pass this as
/// the targets URL.
pub(crate) const UNUSED_URL: &str = "file:///unused/url";

/// Load a repo for metadata processing only.
pub(crate) async fn load_metadata_repo(
    root: &str,
    metadata_url: Url,
    s3_region: Option<&str>,
) -> Result<Repository> {
    let root_bytes = read_root_bytes(root, s3_region).await?;
    RepositoryLoader::new(
        &root_bytes,
        metadata_url,
        Url::parse(UNUSED_URL).with_context(|_| error::UrlParseSnafu {
            url: UNUSED_URL.to_owned(),
        })?,
    )
    .load()
    .await
    .context(error::RepoLoadSnafu)
}

#[cfg(feature = "s3")]
pub(crate) async fn read_root_bytes(root: &str, s3_region: Option<&str>) -> Result<Vec<u8>> {
    use futures::TryStreamExt;
    use tough::Transport;
    if root.starts_with("s3://") {
        let region = s3_region.ok_or_else(|| {
            error::MissingSnafu {
                what: "--s3-region required for S3 URIs".to_string(),
            }
            .build()
        })?;
        let transport = S3Transport::new_with_region(region).await;
        let url = Url::parse(root).context(error::UrlParseSnafu { url: root })?;
        let stream = transport
            .fetch(url)
            .await
            .map_err(|e| error::Error::Transport {
                source: Box::new(e),
                backtrace: snafu::Backtrace::new(),
            })?;
        return stream
            .try_fold(Vec::new(), |mut acc, chunk| async move {
                acc.extend_from_slice(&chunk);
                Ok(acc)
            })
            .await
            .map_err(|e| error::Error::Transport {
                source: Box::new(e),
                backtrace: snafu::Backtrace::new(),
            });
    }
    tokio::fs::read(root)
        .await
        .context(error::OpenRootSnafu { path: root })
}

#[cfg(not(feature = "s3"))]
pub(crate) async fn read_root_bytes(root: &str, _s3_region: Option<&str>) -> Result<Vec<u8>> {
    tokio::fs::read(root)
        .await
        .context(error::OpenRootSnafu { path: root })
}

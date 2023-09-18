/// This module is for code that is re-used by different `tuftool` subcommands.
use crate::error::{self, Result};
use snafu::ResultExt;
use std::path::Path;
use tough::{Repository, RepositoryLoader};
use url::Url;

/// Some commands only deal with metadata and never use a targets directory.
/// When loading a repo that does not need a targets directory, we pass this as
/// the targets URL.
pub(crate) const UNUSED_URL: &str = "file:///unused/url";

/// Load a repo for metadata processing only. Such a repo will never use the
/// targets directory, so a dummy path is passed.
///
/// - `root` must be a path to a file that can be opened with `File::open`.
/// - `metadata_url` can be local or remote.
///
pub(crate) async fn load_metadata_repo<P>(root: P, metadata_url: Url) -> Result<Repository>
where
    P: AsRef<Path>,
{
    let root = root.as_ref();
    RepositoryLoader::new(
        &tokio::fs::read(root)
            .await
            .context(error::OpenRootSnafu { path: root })?,
        metadata_url,
        // we don't do anything with the targets url for metadata operations
        Url::parse(UNUSED_URL).with_context(|_| error::UrlParseSnafu {
            url: UNUSED_URL.to_owned(),
        })?,
    )
    .load()
    .await
    .context(error::RepoLoadSnafu)
}

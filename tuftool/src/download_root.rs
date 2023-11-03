// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `download_root` module owns the logic for downloading a given version of `root.json`.

use crate::error::{self, Result};
use futures::StreamExt;
use snafu::ResultExt;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use url::Url;

/// Download the given version of `root.json`
/// This is an unsafe operation, and doesn't establish trust. It should only be used for testing!
pub(crate) async fn download_root<P>(
    metadata_base_url: &Url,
    version: NonZeroU64,
    outdir: P,
) -> Result<PathBuf>
where
    P: AsRef<Path>,
{
    let name = format!("{version}.root.json");

    let path = outdir.as_ref().join(&name);
    let url = metadata_base_url
        .join(&name)
        .context(error::UrlParseSnafu {
            url: format!("{name}/{}", metadata_base_url.as_str()),
        })?;
    root_warning(&path);

    let root_request = reqwest::get(url.as_str())
        .await
        .context(error::ReqwestGetSnafu)?
        .error_for_status()
        .context(error::BadResponseSnafu { url })?;

    let mut f = File::create(&path)
        .await
        .context(error::OpenFileSnafu { path: &path })?;

    let bytes_stream = &mut root_request.bytes_stream();
    while let Some(bytes) = bytes_stream.next().await {
        let bytes = bytes.context(error::ReqwestCopySnafu)?;
        f.write_all(&bytes)
            .await
            .with_context(|_| error::FileWriteSnafu { path: path.clone() })?;
    }

    Ok(path)
}

/// Print a very noticeable warning message about the unsafe nature of downloading `root.json`
/// without verification
fn root_warning<P: AsRef<Path>>(path: P) {
    #[rustfmt::skip]
    eprintln!("\
=================================================================
WARNING: Downloading root.json to {}
This is unsafe and will not establish trust, use only for testing
=================================================================",
              path.as_ref().display());
}

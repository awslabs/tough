// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `download_root` module owns the logic for downloading a given version of `root.json`.

use crate::error::{self, Result};
use snafu::ResultExt;
use std::fs::File;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use url::Url;

/// Download the given version of `root.json`
/// This is an unsafe operation, and doesn't establish trust. It should only be used for testing!
pub(crate) fn download_root<P>(
    metadata_base_url: &Url,
    version: NonZeroU64,
    outdir: P,
) -> Result<PathBuf>
where
    P: AsRef<Path>,
{
    let name = format!("{}.root.json", version);

    let path = outdir.as_ref().join(&name);
    let url = metadata_base_url.join(&name).context(error::UrlParse {
        url: format!("{}/{}", metadata_base_url.as_str(), name),
    })?;
    root_warning(&path);

    let mut root_request = reqwest::blocking::get(url.as_str())
        .context(error::ReqwestGet)?
        .error_for_status()
        .context(error::BadResponse { url })?;

    let mut f = File::create(&path).context(error::OpenFile { path: &path })?;
    root_request.copy_to(&mut f).context(error::ReqwestCopy)?;

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

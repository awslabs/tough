// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::{Path, PathBuf};
use url::Url;

/// Returns the path to our test data directory
pub fn test_data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
}

/// Converts a filepath into a URI formatted string
pub fn dir_url<P: AsRef<Path>>(path: P) -> String {
    Url::from_directory_path(path).unwrap().to_string()
}

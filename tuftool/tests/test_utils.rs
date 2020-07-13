// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::Read;
use std::path::{Path, PathBuf};
use url::Url;

/// Utilities for tests. Not every test module uses every function, so we suppress unused warnings.

/// Returns the path to our test data directory
#[allow(unused)]
pub fn test_data() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.join("tough").join("tests").join("data")
}

/// Converts a filepath into a URI formatted string
#[allow(unused)]
pub fn dir_url<P: AsRef<Path>>(path: P) -> String {
    Url::from_directory_path(path).unwrap().to_string()
}

/// Returns a vector of bytes from any object with the Read trait
#[allow(unused)]
pub fn read_to_end<R: Read>(mut reader: R) -> Vec<u8> {
    let mut v = Vec::new();
    reader.read_to_end(&mut v).unwrap();
    v
}

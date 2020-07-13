use std::io::Read;
use std::path::{Path, PathBuf};
use url::Url;

/// Returns the path to our test data directory
pub fn test_data() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.join("tough").join("tests").join("data")
}

/// Converts a filepath into a URI formatted string
pub fn dir_url<P: AsRef<Path>>(path: P) -> String {
    Url::from_directory_path(path).unwrap().to_string()
}

/// Returns a vector of bytes from any object with the Read trait
pub fn read_to_end<R: Read>(mut reader: R) -> Vec<u8> {
    let mut v = Vec::new();
    reader.read_to_end(&mut v).unwrap();
    v
}

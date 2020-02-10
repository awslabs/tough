use crate::error;
use crate::error::Result;
use crate::key::RootKeys;
use crate::source::KeySource;
use ring::digest::{SHA256, SHA256_OUTPUT_LEN};
use snafu::ensure;
use snafu::ResultExt;
use std::collections::HashMap;
use std::path::PathBuf;
use tough::schema::{Root, Signed};

/// Represents a loaded root.json file along with its sha256 digest and size in bytes
pub(crate) struct RootDigest {
    /// The loaded Root object
    pub(crate) root: Root,
    /// The sha256 digest of the root.json file
    pub(crate) digest: [u8; SHA256_OUTPUT_LEN],
    /// The size (in bytes) of the root.json
    pub(crate) size: u64,
}

impl RootDigest {
    /// Constructs a `RootDigest` object by parsing a `root.json` file
    ///
    /// # Arguments
    ///
    /// * `path` - The filepath to a `root.json` file
    ///
    ///  # Return
    ///
    /// * Either an Error, or a constructed `RootDigest`
    ///
    pub(crate) fn load(path: &PathBuf) -> Result<Self> {
        let root_buf = std::fs::read(path).context(error::FileRead { path })?;
        let root = serde_json::from_slice::<Signed<Root>>(&root_buf)
            .context(error::FileParseJson { path })?
            .signed;
        let mut digest = [0; SHA256_OUTPUT_LEN];
        digest.copy_from_slice(ring::digest::digest(&SHA256, &root_buf).as_ref());
        let size = root_buf.len() as u64;
        Ok(RootDigest { root, digest, size })
    }

    /// Searches `KeySources` to match them with the keys that are designated in the `root.json`
    /// file.
    ///
    /// # Arguments
    ///
    /// * `keys` - The list of `KeySources` (i.e. private keys) to search
    ///
    /// # Return
    ///
    /// * A map of private keys identifiable by their names as defined in `root.json`
    ///
    /// # Errors
    ///
    /// * An error can occur for io reasons
    ///
    pub(crate) fn load_keys(&self, keys: &[KeySource]) -> Result<RootKeys> {
        let mut map = HashMap::new();
        for source in keys {
            let key_pair = source.as_sign()?;
            if let Some((keyid, _)) = self
                .root
                .keys
                .iter()
                .find(|(_, key)| key_pair.tuf_key() == **key)
            {
                map.insert(keyid.clone(), key_pair);
            }
        }
        ensure!(!map.is_empty(), error::KeysNotFoundInRoot {});
        Ok(map)
    }
}

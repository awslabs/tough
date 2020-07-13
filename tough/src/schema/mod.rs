#![allow(clippy::used_underscore_binding)] // #20

//! Provides the schema objects as defined by the TUF spec.

mod de;
pub mod decoded;
mod error;
mod iter;
pub mod key;
mod spki;
mod verify;

pub use crate::schema::error::{Error, Result};

use crate::schema::decoded::{Decoded, Hex};
use crate::schema::iter::KeysIter;
use crate::schema::key::Key;
use crate::sign::Sign;
pub use crate::transport::{FilesystemTransport, Transport};
use chrono::{DateTime, Utc};
use globset::Glob;
use olpc_cjson::CanonicalFormatter;
use ring::digest::{digest, Context, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_plain::{forward_display_to_serde, forward_from_str_to_serde};
use snafu::ResultExt;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::num::NonZeroU64;
use std::path::Path;

/// The type of metadata role.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum RoleType {
    /// The root role delegates trust to specific keys trusted for all other top-level roles used in
    /// the system.
    Root,
    /// The snapshot role signs a metadata file that provides information about the latest version
    /// of all targets metadata on the repository (the top-level targets role and all delegated
    /// roles).
    Snapshot,
    /// The targets role's signature indicates which target files are trusted by clients.
    Targets,
    /// The timestamp role is used to prevent an adversary from replaying an out-of-date signed
    /// metadata file whose signature has not yet expired.
    Timestamp,
}

forward_display_to_serde!(RoleType);
forward_from_str_to_serde!(RoleType);

/// Common trait implemented by all roles.
pub trait Role: Serialize {
    /// The type of role this object represents.
    const TYPE: RoleType;

    /// Determines when metadata should be considered expired and no longer trusted by clients.
    fn expires(&self) -> DateTime<Utc>;

    /// An integer that is greater than 0. Clients MUST NOT replace a metadata file with a version
    /// number less than the one currently trusted.
    fn version(&self) -> NonZeroU64;

    /// A deterministic JSON serialization used when calculating the digest of a metadata object.
    /// [More info on canonical JSON](http://wiki.laptop.org/go/Canonical_JSON)
    fn canonical_form(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut data, CanonicalFormatter::new());
        self.serialize(&mut ser)
            .context(error::JsonSerialization { what: "role" })?;
        Ok(data)
    }
}

/// A signed metadata object.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Signed<T> {
    /// The role that is signed.
    pub signed: T,
    /// A list of signatures and their key IDs.
    pub signatures: Vec<Signature>,
}

/// A signature and the key ID that made it.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Signature {
    /// The key ID (listed in root.json) that made this signature.
    pub keyid: Decoded<Hex>,
    /// A hex-encoded signature of the canonical JSON form of a role.
    pub sig: Decoded<Hex>,
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// TUF 4.3: The root.json file is signed by the root role's keys. It indicates which keys are
/// authorized for all top-level roles, including the root role itself. Revocation and replacement
/// of top-level role keys, including for the root role, is done by changing the keys listed for the
/// roles in this file.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "_type")]
#[serde(rename = "root")]
pub struct Root {
    /// A string that contains the version number of the TUF specification. Its format follows the
    /// Semantic Versioning 2.0.0 (semver) specification.
    pub spec_version: String,

    /// A boolean indicating whether the repository supports consistent snapshots. When consistent
    /// snapshots is `true`, targets and certain metadata filenames are prefixed with either a
    /// a version number or digest.
    pub consistent_snapshot: bool,

    /// An integer that is greater than 0. Clients MUST NOT replace a metadata file with a version
    /// number less than the one currently trusted.
    pub version: NonZeroU64,

    /// Determines when metadata should be considered expired and no longer trusted by clients.
    pub expires: DateTime<Utc>,

    /// The KEYID must be correct for the specified KEY. Clients MUST calculate each KEYID to verify
    /// this is correct for the associated key. Clients MUST ensure that for any KEYID represented
    /// in this key list and in other files, only one unique key has that KEYID.
    #[serde(deserialize_with = "de::deserialize_keys")]
    pub keys: HashMap<Decoded<Hex>, Key>,

    /// A list of roles, the keys associated with each role, and the threshold of signatures used
    /// for each role.
    pub roles: HashMap<RoleType, RoleKeys>,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    #[serde(deserialize_with = "de::extra_skip_type")]
    pub _extra: HashMap<String, Value>,
}

/// Represents the key IDs used for a role and the threshold of signatures required to validate it.
/// TUF 4.3: A ROLE is one of "root", "snapshot", "targets", "timestamp", or "mirrors". A role for
/// each of "root", "snapshot", "timestamp", and "targets" MUST be specified in the key list.
/// The role of "mirror" is optional. If not specified, the mirror list will not need to be signed
/// if mirror lists are being used. The THRESHOLD for a role is an integer of the number of keys of
/// that role whose signatures are required in order to consider a file as being properly signed by
/// that role.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RoleKeys {
    /// The key IDs used for the role.
    pub keyids: Vec<Decoded<Hex>>,

    /// The threshold of signatures required to validate the role.
    pub threshold: NonZeroU64,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

impl Root {
    /// An iterator over the keys for a given role.
    pub fn keys(&self, role: RoleType) -> impl Iterator<Item = &Key> {
        KeysIter {
            keyids_iter: match self.roles.get(&role) {
                Some(role_keys) => role_keys.keyids.iter(),
                None => [].iter(),
            },
            keys: &self.keys,
        }
    }

    /// Given an object/key that impls Sign, return the corresponding
    /// key ID from Root
    pub fn key_id(&self, key_pair: &dyn Sign) -> Option<Decoded<Hex>> {
        for (key_id, key) in &self.keys {
            if key_pair.tuf_key() == *key {
                return Some(key_id.clone());
            }
        }
        None
    }
}

impl Role for Root {
    const TYPE: RoleType = RoleType::Root;

    fn expires(&self) -> DateTime<Utc> {
        self.expires
    }

    fn version(&self) -> NonZeroU64 {
        self.version
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// TUF 4.4 The snapshot.json file is signed by the snapshot role. It MUST list the version numbers
/// of the top-level targets metadata and all delegated targets metadata. It MAY also list their
/// lengths and file hashes.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "_type")]
#[serde(rename = "snapshot")]
pub struct Snapshot {
    /// A string that contains the version number of the TUF specification. Its format follows the
    /// Semantic Versioning 2.0.0 (semver) specification.
    pub spec_version: String,

    /// An integer that is greater than 0. Clients MUST NOT replace a metadata file with a version
    /// number less than the one currently trusted.
    pub version: NonZeroU64,

    /// Determines when metadata should be considered expired and no longer trusted by clients.
    pub expires: DateTime<Utc>,

    /// A list of what the TUF spec calls 'METAFILES' (`SnapshotMeta` objects). The TUF spec
    /// describes the hash key in 4.4: METAPATH is the file path of the metadata on the repository
    /// relative to the metadata base URL. For snapshot.json, these are top-level targets metadata
    /// and delegated targets metadata.
    pub meta: HashMap<String, SnapshotMeta>,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    #[serde(deserialize_with = "de::extra_skip_type")]
    pub _extra: HashMap<String, Value>,
}

/// Represents a metadata file in a `snapshot.json` file.
/// TUF 4.4: METAFILES is an object whose format is the following:
/// ```text
///  { METAPATH : {
///        "version" : VERSION,
///        ("length" : LENGTH, |
///         "hashes" : HASHES) }
///    , ...
///  }
/// ```
/// e.g.
/// ```json
///    "project1.json": {
///     "version": 1,
///     "hashes": {
///      "sha256": "f592d072e1193688a686267e8e10d7257b4ebfcf28133350dae88362d82a0c8a"
///     }
///    },
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SnapshotMeta {
    /// LENGTH is the integer length in bytes of the metadata file at METAPATH. It is OPTIONAL and
    /// can be omitted to reduce the snapshot metadata file size. In that case the client MUST use a
    /// custom download limit for the listed metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,

    /// HASHES is a dictionary that specifies one or more hashes of the metadata file at METAPATH,
    /// including their cryptographic hash function. For example: `{ "sha256": HASH, ... }`. HASHES
    /// is OPTIONAL and can be omitted to reduce the snapshot metadata file size. In that case the
    /// repository MUST guarantee that VERSION alone unambiguously identifies the metadata at
    /// METAPATH.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Hashes>,

    /// An integer that is greater than 0. Clients MUST NOT replace a metadata file with a version
    /// number less than the one currently trusted.
    pub version: NonZeroU64,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

/// Represents the hash dictionary in a `snapshot.json` file.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Hashes {
    /// The SHA 256 digest of a metadata file.
    pub sha256: Decoded<Hex>,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

impl Snapshot {
    /// Create a new `Snapshot` object.
    pub fn new(spec_version: String, version: NonZeroU64, expires: DateTime<Utc>) -> Self {
        Snapshot {
            spec_version,
            version,
            expires,
            meta: HashMap::new(),
            _extra: HashMap::new(),
        }
    }
}
impl Role for Snapshot {
    const TYPE: RoleType = RoleType::Snapshot;

    fn expires(&self) -> DateTime<Utc> {
        self.expires
    }

    fn version(&self) -> NonZeroU64 {
        self.version
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// Represents a `targets.json` file.
/// TUF 4.5:
/// The "signed" portion of targets.json is as follows:
/// ```text
/// { "_type" : "targets",
///   "spec_version" : SPEC_VERSION,
///   "version" : VERSION,
///   "expires" : EXPIRES,
///   "targets" : TARGETS,
///   ("delegations" : DELEGATIONS)
/// }
/// ```
///
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "_type")]
#[serde(rename = "targets")]
pub struct Targets {
    /// A string that contains the version number of the TUF specification. Its format follows the
    /// Semantic Versioning 2.0.0 (semver) specification.
    pub spec_version: String,

    /// An integer that is greater than 0. Clients MUST NOT replace a metadata file with a version
    /// number less than the one currently trusted.
    pub version: NonZeroU64,

    /// Determines when metadata should be considered expired and no longer trusted by clients.
    pub expires: DateTime<Utc>,

    /// Each key of the TARGETS object is a TARGETPATH. A TARGETPATH is a path to a file that is
    /// relative to a mirror's base URL of targets.
    pub targets: HashMap<String, Target>,

    /// Delegations describes subsets of the targets for which responsibility is delegated to
    /// another role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegations: Option<Delegations>,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    #[serde(deserialize_with = "de::extra_skip_type")]
    pub _extra: HashMap<String, Value>,
}

/// TUF 4.5: TARGETS is an object whose format is the following:
/// ```text
/// { TARGETPATH : {
///       "length" : LENGTH,
///       "hashes" : HASHES,
///       ("custom" : { ... }) }
///   , ...
/// }
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Target {
    /// LENGTH is the integer length in bytes of the target file at TARGETPATH.
    pub length: u64,

    /// HASHES is a dictionary that specifies one or more hashes, including the cryptographic hash
    /// function. For example: `{ "sha256": HASH, ... }`. HASH is the hexdigest of the cryptographic
    /// function computed on the target file.
    pub hashes: Hashes,

    /// If defined, the elements and values of "custom" will be made available to the client
    /// application. The information in "custom" is opaque to the framework and can include version
    /// numbers, dependencies, requirements, and any other data that the application wants to
    /// include to describe the file at TARGETPATH. The application may use this information to
    /// guide download decisions.
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom: HashMap<String, Value>,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

impl Target {
    /// Given a path, returns a Target struct
    pub fn from_path<P>(path: P) -> Result<Target>
    where
        P: AsRef<Path>,
    {
        // Ensure the given path is a file
        let path = path.as_ref();
        if !path.is_file() {
            return error::TargetNotAFile { path }.fail();
        }

        // Get the sha256 and length of the target
        let mut file = File::open(path).context(error::FileOpen { path })?;
        let mut digest = Context::new(&SHA256);
        let mut buf = [0; 8 * 1024];
        let mut length = 0;
        loop {
            match file.read(&mut buf).context(error::FileRead { path })? {
                0 => break,
                n => {
                    digest.update(&buf[..n]);
                    length += n as u64;
                }
            }
        }

        Ok(Target {
            length,
            hashes: Hashes {
                sha256: Decoded::from(digest.finish().as_ref().to_vec()),
                _extra: HashMap::new(),
            },
            custom: HashMap::new(),
            _extra: HashMap::new(),
        })
    }
}

impl Targets {
    /// Create a new `Targets` object.
    pub fn new(spec_version: String, version: NonZeroU64, expires: DateTime<Utc>) -> Self {
        Targets {
            spec_version,
            version,
            expires,
            targets: HashMap::new(),
            _extra: HashMap::new(),
            delegations: Some(Delegations::new()),
        }
    }

    /// Given a target url, returns a reference to the Target struct or error if the target is unreachable
    pub fn find_target(&self, target_name: &str) -> Result<&Target> {
        match self.targets.get(target_name) {
            Some(target) => Ok(target),
            None => match &self.delegations {
                None => Err(Error::TargetNotFound {
                    target_file: target_name.to_string(),
                }),
                Some(delegations) => delegations.find_target(target_name),
            },
        }
    }

    /// Given the name of a delegated role, return the delegated role
    pub fn delegated_role(&self, name: &str) -> Result<&DelegatedRole> {
        if let Some(delegations) = &self.delegations {
            return delegations.delegated_role(name);
        }
        Err(Error::NoDelegations {})
    }

    /// Returns an iterator of all targets delegated recursively
    pub fn targets_iter<'a>(&'a self) -> impl Iterator + 'a {
        self.targets_vec().into_iter()
    }

    /// Returns a vec of all targets and all delegated targets recursively
    pub fn targets_vec(&self) -> Vec<&Target> {
        let mut targets = Vec::new();
        for target in &self.targets {
            targets.push(target.1);
        }
        if let Some(delegations) = &self.delegations {
            for t in delegations.targets_vec() {
                targets.push(t);
            }
        }

        targets
    }

    /// Returns a hashmap of all targets and all delegated targets recursively
    pub fn targets_map(&self) -> HashMap<String, &Target> {
        let mut targets = HashMap::new();
        for target in &self.targets {
            targets.insert(target.0.clone(), target.1);
        }
        if let Some(delegations) = &self.delegations {
            targets.extend(delegations.targets_map());
        }

        targets
    }

    ///Returns a hashmap of all targets and all delegated targets recursively with consistent snapshot names
    pub fn targets_map_consistent(&self) -> HashMap<String, &Target> {
        let mut targets = HashMap::new();
        for target in &self.targets {
            targets.insert(
                format!(
                    "{}.{}",
                    hex::encode(&target.1.hashes.sha256),
                    target.0.clone()
                ),
                target.1,
            );
        }
        if let Some(delegations) = &self.delegations {
            targets.extend(delegations.targets_map_consistent());
        }

        targets
    }

    ///Returns a vec of all rolenames
    pub fn role_names(&self) -> Vec<&String> {
        let mut roles = Vec::new();
        if let Some(delelegations) = &self.delegations {
            for role in &delelegations.roles {
                roles.push(&role.name);
                if let Some(targets) = &role.targets {
                    roles.append(&mut targets.signed.role_names())
                }
            }
        }

        roles
    }

    ///recursively clears all targets
    pub fn clear_targets(&mut self) {
        self.targets = HashMap::new();
        if let Some(delegations) = &mut self.delegations {
            for del_role in &mut delegations.roles {
                if let Some(targets) = &mut del_role.targets {
                    targets.signed.clear_targets();
                }
            }
        }
    }

    /// Finds a targets by its `name`
    pub fn targets_by_name(&mut self, name: &str) -> Result<&mut Self> {
        if let Some(delegations) = &mut self.delegations {
            for role in &mut delegations.roles {
                if let Some(targets) = &mut role.targets {
                    if role.name == name {
                        return Ok(&mut targets.signed);
                    } else if let Ok(role) = targets.signed.targets_by_name(name) {
                        return Ok(role);
                    }
                }
            }
        }
        Err(Error::RoleNotFound {
            name: name.to_string(),
        })
    }

    /// Finds a targets role and verifies that it has access to `path`
    pub fn targets_by_name_verify_path(&mut self, name: &str, path: &str) -> Result<&mut Self> {
        if let Some(delegations) = &mut self.delegations {
            for role in &mut delegations.roles {
                // If the path is not delegated to this role there is no need to continue searching for it
                if !role.paths.matched_target(path) {
                    continue;
                }
                if let Some(targets) = &mut role.targets {
                    if role.name == name {
                        return Ok(&mut targets.signed);
                    } else if let Ok(role) = targets.signed.targets_by_name(name) {
                        return Ok(role);
                    }
                }
            }
        }
        Err(Error::RoleNotFound {
            name: name.to_string(),
        })
    }

    /// Returns a result with the `Signed<Targets>` called `name`
    pub fn signed_targets_by_name(&self, name: &str) -> Result<&Signed<Self>> {
        if let Some(delegations) = &self.delegations {
            for role in &delegations.roles {
                if let Some(targets) = &role.targets {
                    if role.name == name {
                        return Ok(&targets);
                    } else if let Ok(role) = targets.signed.signed_targets_by_name(name) {
                        return Ok(role);
                    }
                }
            }
        }
        Err(Error::RoleNotFound {
            name: name.to_string(),
        })
    }

    /// Add a target to targets
    pub fn add_target(&mut self, name: &str, target: Target) {
        self.targets.insert(name.to_string(), target);
    }

    /// Remove a target from targets
    pub fn remove_target(&mut self, name: &str) -> Option<Target> {
        self.targets.remove(name)
    }

    /// Returns a vec of all rolenames
    pub fn get_roles_str(&self) -> Vec<&String> {
        let mut roles = Vec::new();
        if let Some(del) = &self.delegations {
            for role in &del.roles {
                roles.push(&role.name);
                if let Some(targets) = &role.targets {
                    roles.append(&mut targets.signed.get_roles_str())
                }
            }
        }

        roles
    }

    /// Returns a result with the `DelegatedRole` called `name`
    pub fn get_delegated_role_by_name(&mut self, name: &str) -> Result<&mut DelegatedRole> {
        if let Some(delegations) = &mut self.delegations {
            for role in &mut delegations.roles {
                if role.name == name {
                    return Ok(role);
                } else if let Some(targets) = &mut role.targets {
                    if let Ok(role) = targets.signed.get_delegated_role_by_name(name) {
                        return Ok(role);
                    }
                }
            }
        }
        Err(Error::RoleNotFound {
            name: name.to_string(),
        })
    }

    /// Returns a reference to the parent delegation of `name`
    pub fn parent_of(&self, name: &str) -> Result<&Delegations> {
        if let Some(delegations) = &self.delegations {
            for role in &delegations.roles {
                if role.name == name {
                    return Ok(&delegations);
                }
                if let Some(targets) = &role.targets {
                    if let Ok(delegation) = targets.signed.parent_of(name) {
                        return Ok(delegation);
                    }
                }
            }
        }
        Err(error::Error::RoleNotFound {
            name: name.to_string(),
        })
    }
}

impl Role for Targets {
    const TYPE: RoleType = RoleType::Targets;

    fn expires(&self) -> DateTime<Utc> {
        self.expires
    }

    fn version(&self) -> NonZeroU64 {
        self.version
    }
}

/// Delegations are found in a `targets.json` file.
/// TUF 4.5: DELEGATIONS is an object whose format is the following:
/// ```text
/// { "keys" : {
///       KEYID : KEY,
///       ... },
///   "roles" : [{
///       "name": ROLENAME,
///       "keyids" : [ KEYID, ... ] ,
///       "threshold" : THRESHOLD,
///       ("path_hash_prefixes" : [ HEX_DIGEST, ... ] |
///        "paths" : [ PATHPATTERN, ... ]),
///       "terminating": TERMINATING,
///   }, ... ]
/// }
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Delegations {
    /// Lists the public keys to verify signatures of delegated targets roles. Revocation and
    /// replacement of delegated targets roles keys is done by changing the keys in this field in
    /// the delegating role's metadata.
    #[serde(deserialize_with = "de::deserialize_keys")]
    pub keys: HashMap<Decoded<Hex>, Key>,

    /// The list of delegated roles.
    pub roles: Vec<DelegatedRole>,
}

/// Each role delegated in a targets file is considered a delegated role
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DelegatedRole {
    /// The name of the delegated role. For example, "projects".
    pub name: String,

    /// The key IDs used by this role.
    pub keyids: Vec<Decoded<Hex>>,

    /// The threshold of signatures required to validate the role.
    pub threshold: NonZeroU64,

    /// The paths governed by this role.
    #[serde(flatten)]
    pub paths: PathSet,

    /// Indicates whether subsequent delegations should be considered.
    pub terminating: bool,

    /// The targets that are signed by this role.
    #[serde(skip)]
    pub targets: Option<Signed<Targets>>,
}

/// Specifies the target paths that a delegated role controls.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum PathSet {
    /// The "paths" list describes paths that the role is trusted to provide. Clients MUST check
    /// that a target is in one of the trusted paths of all roles in a delegation chain, not just in
    /// a trusted path of the role that describes the target file. PATHPATTERN can include shell-
    /// style wildcards and supports the Unix filename pattern matching convention. Its format may
    /// either indicate a path to a single file, or to multiple paths with the use of shell-style
    /// wildcards. For example, the path pattern "targets/*.tgz" would match file paths
    /// "targets/foo.tgz" and "targets/bar.tgz", but not "targets/foo.txt". Likewise, path pattern
    /// "foo-version-?.tgz" matches "foo-version-2.tgz" and "foo-version-a.tgz", but not
    /// "foo-version-alpha.tgz". To avoid surprising behavior when matching targets with
    /// PATHPATTERN, it is RECOMMENDED that PATHPATTERN uses the forward slash (/) as directory
    /// separator and does not start with a directory separator, akin to TARGETSPATH.
    #[serde(rename = "paths")]
    Paths(Vec<String>),

    /// The "path_hash_prefixes" list is used to succinctly describe a set of target paths.
    /// Specifically, each HEX_DIGEST in "path_hash_prefixes" describes a set of target paths;
    /// therefore, "path_hash_prefixes" is the union over each prefix of its set of target paths.
    /// The target paths must meet this condition: each target path, when hashed with the SHA-256
    /// hash function to produce a 64-byte hexadecimal digest (HEX_DIGEST), must share the same
    /// prefix as one of the prefixes in "path_hash_prefixes". This is useful to split a large
    /// number of targets into separate bins identified by consistent hashing.
    #[serde(rename = "path_hash_prefixes")]
    PathHashPrefixes(Vec<String>),
}

impl PathSet {
    /// Given a target string determines if paths match
    fn matched_target(&self, target: &str) -> bool {
        match self {
            Self::Paths(paths) => {
                for path in paths {
                    if Self::matched_path(path, target) {
                        return true;
                    }
                }
            }

            Self::PathHashPrefixes(path_prefixes) => {
                for path in path_prefixes {
                    if Self::matched_prefix(path, target) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Given a path hash prefix and a target path determines if target is delegated by prefix
    fn matched_prefix(prefix: &str, target: &str) -> bool {
        let temp_target = target.to_string();
        let hash = digest(&SHA256, temp_target.as_bytes());
        hash.as_ref().starts_with(prefix.as_bytes())
    }

    /// Given a shell style wildcard path determines if target matches the path
    fn matched_path(wildcardpath: &str, target: &str) -> bool {
        let glob = if let Ok(glob) = Glob::new(wildcardpath) {
            glob.compile_matcher()
        } else {
            return false;
        };
        glob.is_match(target)
    }

    /// Returns a Vec representation of the `PathSet`
    pub fn vec(&self) -> &Vec<String> {
        match self {
            PathSet::Paths(x) | PathSet::PathHashPrefixes(x) => x,
        }
    }
}

impl Delegations {
    /// Creates a new Delegations with no keys or roles
    pub fn new() -> Self {
        Delegations {
            keys: HashMap::new(),
            roles: Vec::new(),
        }
    }

    /// Determines if target passes pathset specific matching
    pub fn target_is_delegated(&self, target: &str) -> bool {
        for role in &self.roles {
            if role.paths.matched_target(target) {
                return true;
            }
        }
        false
    }

    /// Ensures that all delegated paths are allowed to be delegated
    pub fn verify_paths(&self) -> Result<()> {
        for sub_role in &self.roles {
            let pathset = match &sub_role.paths {
                PathSet::Paths(paths) | PathSet::PathHashPrefixes(paths) => paths,
            };
            for path in pathset {
                if !self.target_is_delegated(&path) {
                    return Err(Error::UnmatchedPath {
                        child: path.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Returns given role if its a child of struct
    pub fn role(&self, role_name: &str) -> Option<&DelegatedRole> {
        for role in &self.roles {
            if role.name == role_name {
                return Some(&role);
            }
        }
        None
    }

    /// Finds target using pre ordered search given `target_name` or error if the target is not found
    pub fn find_target(&self, target_name: &str) -> Result<&Target> {
        for delegated_role in &self.roles {
            if delegated_role.paths.matched_target(target_name) {
                if let Some(targets) = &delegated_role.targets {
                    if let Ok(target) = &targets.signed.find_target(target_name) {
                        return Ok(target);
                    }
                }
            }
        }
        Err(Error::TargetNotFound {
            target_file: target_name.to_string(),
        })
    }

    /// Given a role name recursively searches for the delegated role
    pub fn delegated_role(&self, name: &str) -> Result<&DelegatedRole> {
        for delegated_role in &self.roles {
            if delegated_role.name == name {
                return Ok(&delegated_role);
            }
            if let Some(targets) = &delegated_role.targets {
                match targets.signed.delegated_role(name) {
                    Ok(delegations) => return Ok(delegations),
                    Err(_) => continue,
                }
            } else {
                return Err(Error::NoDelegations {});
            }
        }
        Err(Error::TargetNotFound {
            target_file: name.to_string(),
        })
    }

    /// Returns all targets delegated by this struct recursively
    pub fn targets_vec(&self) -> Vec<&Target> {
        let mut targets = Vec::<&Target>::new();
        for role in &self.roles {
            if let Some(t) = &role.targets {
                for t in t.signed.targets_vec() {
                    targets.push(t);
                }
            }
        }
        targets
    }

    /// Returns all targets delegated by this struct recursively
    pub fn targets_map(&self) -> HashMap<String, &Target> {
        let mut targets = HashMap::new();
        for role in &self.roles {
            if let Some(t) = &role.targets {
                targets.extend(t.signed.targets_map());
            }
        }
        targets
    }

    ///Returns all targets delegated by this struct recursively with consistent snapshot prefixes
    pub fn targets_map_consistent(&self) -> HashMap<String, &Target> {
        let mut targets = HashMap::new();
        for role in &self.roles {
            if let Some(t) = &role.targets {
                targets.extend(t.signed.targets_map_consistent());
            }
        }
        targets
    }

    /// Given an object/key that impls Sign, return the corresponding
    /// key ID from Delegation
    pub fn key_id(&self, key_pair: &dyn Sign) -> Option<Decoded<Hex>> {
        for (key_id, key) in &self.keys {
            if key_pair.tuf_key() == *key {
                return Some(key_id.clone());
            }
        }
        None
    }
}

impl DelegatedRole {
    /// Returns a `RoleKeys` representation of the role
    pub fn keys(&self) -> RoleKeys {
        RoleKeys {
            keyids: self.keyids.clone(),
            threshold: self.threshold,
            _extra: HashMap::new(),
        }
    }

    /// link all current targets to `new_targets` metadata, returns a list of `new_targets` not included in the original targets
    pub fn update_targets(&mut self, mut new_targets: Signed<Targets>) -> Vec<String> {
        let mut needed_roles = Vec::new();
        // Copy existing targets into proper places of new_targets
        if let Some(targets) = &self.targets {
            if let Some(delegations) = &mut new_targets.signed.delegations {
                for mut role in &mut delegations.roles {
                    // find the corresponding targets for role
                    if let Ok(targets) = targets.signed.signed_targets_by_name(&role.name) {
                        role.targets = Some(targets.clone());
                    } else {
                        needed_roles.push(role.name.clone());
                    }
                }
            }
        }

        // Copy new targets to existing targets
        self.targets = Some(new_targets);

        // Return the roles that did not have existing targets loaded
        needed_roles
    }

    /// Verify that paths can be delegated by this role
    pub fn verify_paths(&self, paths: &PathSet) -> Result<()> {
        let paths = match paths {
            PathSet::Paths(x) | PathSet::PathHashPrefixes(x) => x,
        };
        for path in paths {
            if !self.paths.matched_target(&path) {
                return Err(Error::UnmatchedPath {
                    child: path.to_string(),
                });
            }
        }
        Ok(())
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// Represents a `timestamp.json` file.
/// TUF 4.6: The timestamp file is signed by a timestamp key. It indicates the latest version of the
/// snapshot metadata and is frequently resigned to limit the amount of time a client can be kept
/// unaware of interference with obtaining updates.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "_type")]
#[serde(rename = "timestamp")]
pub struct Timestamp {
    /// A string that contains the version number of the TUF specification. Its format follows the
    /// Semantic Versioning 2.0.0 (semver) specification.
    pub spec_version: String,

    /// An integer that is greater than 0. Clients MUST NOT replace a metadata file with a version
    /// number less than the one currently trusted.
    pub version: NonZeroU64,

    /// Determines when metadata should be considered expired and no longer trusted by clients.
    pub expires: DateTime<Utc>,

    /// METAFILES is the same as described for the snapshot.json file. In the case of the
    /// timestamp.json file, this MUST only include a description of the snapshot.json file.
    pub meta: HashMap<String, TimestampMeta>,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    #[serde(deserialize_with = "de::extra_skip_type")]
    pub _extra: HashMap<String, Value>,
}

/// METAFILES is the same as described for the snapshot.json file. In the case of the timestamp.json
/// file, this MUST only include a description of the snapshot.json file.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TimestampMeta {
    /// The integer length in bytes of the snapshot.json file.
    pub length: u64,

    /// The hashes of the snapshot.json file.
    pub hashes: Hashes,

    /// An integer that is greater than 0. Clients MUST NOT replace a metadata file with a version
    /// number less than the one currently trusted.
    pub version: NonZeroU64,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

impl Timestamp {
    /// Creates a new `Timestamp` object.
    pub fn new(spec_version: String, version: NonZeroU64, expires: DateTime<Utc>) -> Self {
        Timestamp {
            spec_version,
            version,
            expires,
            meta: HashMap::new(),
            _extra: HashMap::new(),
        }
    }
}

impl Role for Timestamp {
    const TYPE: RoleType = RoleType::Timestamp;

    fn expires(&self) -> DateTime<Utc> {
        self.expires
    }

    fn version(&self) -> NonZeroU64 {
        self.version
    }
}

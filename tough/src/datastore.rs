// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{self, Result};
use chrono::{DateTime, Utc};
use log::debug;
use serde::Serialize;
use snafu::{ensure, ResultExt};
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tempfile::TempDir;

/// `Datastore` persists TUF metadata files.
#[derive(Debug, Clone)]
pub(crate) struct Datastore {
    /// A lock around retrieving the datastore path.
    path_lock: Arc<RwLock<DatastorePath>>,
    /// A lock to treat the system_time function as a critical section.
    time_lock: Arc<RwLock<()>>,
}

impl Datastore {
    pub(crate) fn new(path: Option<PathBuf>) -> Result<Self> {
        Ok(Self {
            path_lock: Arc::new(RwLock::new(match path {
                None => DatastorePath::TempDir(TempDir::new().context(error::DatastoreInitSnafu)?),
                Some(p) => DatastorePath::Path(p),
            })),
            time_lock: Arc::new(RwLock::new(())),
        })
    }

    // Because we are not actually changing the underlying data in the lock, we can ignore when a
    // lock is poisoned.

    fn read(&self) -> RwLockReadGuard<'_, DatastorePath> {
        self.path_lock
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, DatastorePath> {
        self.path_lock
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Get a reader to a file in the datastore. Caution, this is *not* thread safe. A lock is
    /// briefly created on the datastore when the read object is created, but it is released at the
    /// end of this function.
    ///
    /// TODO: [provide a thread safe interface](https://github.com/awslabs/tough/issues/602)
    ///
    pub(crate) fn reader(&self, file: &str) -> Result<Option<impl Read>> {
        let path = self.read().path().join(file);
        match File::open(&path) {
            Ok(file) => Ok(Some(file)),
            Err(err) => match err.kind() {
                ErrorKind::NotFound => Ok(None),
                _ => Err(err).context(error::DatastoreOpenSnafu { path: &path }),
            },
        }
    }

    /// Writes a JSON metadata file in the datastore. This function is thread safe.
    pub(crate) fn create<T: Serialize>(&self, file: &str, value: &T) -> Result<()> {
        let path = self.write().path().join(file);
        serde_json::to_writer_pretty(
            File::create(&path).context(error::DatastoreCreateSnafu { path: &path })?,
            value,
        )
        .context(error::DatastoreSerializeSnafu {
            what: format!("{file} in datastore"),
            path,
        })
    }

    /// Deletes a file from the datastore. This function is thread safe.
    pub(crate) fn remove(&self, file: &str) -> Result<()> {
        let path = self.write().path().join(file);
        debug!("removing '{}'", path.display());
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) => match err.kind() {
                ErrorKind::NotFound => Ok(()),
                _ => Err(err).context(error::DatastoreRemoveSnafu { path: &path }),
            },
        }
    }

    /// Ensures that system time has not stepped backward since it was last sampled. This function
    /// is protected by a lock guard to ensure thread safety.
    pub(crate) fn system_time(&self) -> Result<DateTime<Utc>> {
        // Treat this function as a critical section. This lock is not used for anything else.
        let lock = self.time_lock.write().map_err(|e| {
            // Painful error type that has a reference and lifetime. Convert it to a message string.
            error::DatastoreTimeLockSnafu {
                message: e.to_string(),
            }
            .build()
        })?;

        let file = "latest_known_time.json";
        // Load the latest known system time, if it exists
        let poss_latest_known_time = self
            .reader(file)?
            .map(serde_json::from_reader::<_, DateTime<Utc>>);

        // Get 'current' system time
        let sys_time = Utc::now();

        if let Some(Ok(latest_known_time)) = poss_latest_known_time {
            // Make sure the sampled system time did not go back in time
            ensure!(
                sys_time >= latest_known_time,
                error::SystemTimeSteppedBackwardSnafu {
                    sys_time,
                    latest_known_time
                }
            );
        }
        // Store the latest known time
        // Serializes RFC3339 time string and store to datastore
        self.create(file, &sys_time)?;

        // Explicitly drop the lock to avoid any compiler optimization.
        drop(lock);
        Ok(sys_time)
    }
}

/// Because `TempDir` is an RAII object, we need to hold on to it. This private enum allows us to
/// hold either a `TempDir` or a `PathBuf` depending on whether or not the user wants to manage the
/// directory.
#[derive(Debug)]
enum DatastorePath {
    /// Path to a user-managed directory.
    Path(PathBuf),
    /// A `TempDir` that we created on the user's behalf.
    TempDir(TempDir),
}

impl DatastorePath {
    /// Provides convenient access to the underlying filepath.
    fn path(&self) -> &Path {
        match self {
            DatastorePath::Path(p) => p,
            DatastorePath::TempDir(t) => t.path(),
        }
    }
}

use crate::error::{self, Result};
use crate::fetch::{fetch_max_size, fetch_sha256};
use crate::schema::{RoleType, Target};
use crate::transport::IntoVec;
use crate::{encode_filename, Prefix, Repository, TargetName};
use bytes::Bytes;
use futures::StreamExt;
use futures_core::stream::BoxStream;
use snafu::{futures::TryStreamExt, OptionExt, ResultExt};
use std::path::Path;
use tokio::io::AsyncWriteExt;

impl Repository {
    /// Cache an entire or partial repository to disk, including all required metadata.
    /// The cached repo will be local, using filesystem paths.
    ///
    /// * `metadata_outdir` is the directory where cached metadata files will be saved.
    /// * `targets_outdir` is the directory where cached targets files will be saved.
    /// * `targets_subset` is the list of targets to include in the cached repo. If no subset is
    ///   specified (`None`), then *all* targets are included in the cache.
    /// * `cache_root_chain` specifies whether or not we will cache all versions of `root.json`.
    pub async fn cache<P1, P2, S>(
        &self,
        metadata_outdir: P1,
        targets_outdir: P2,
        targets_subset: Option<&[S]>,
        cache_root_chain: bool,
    ) -> Result<()>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
        S: AsRef<str>,
    {
        // Create the output directories if the do not exist.
        tokio::fs::create_dir_all(metadata_outdir.as_ref())
            .await
            .context(error::CacheDirectoryCreateSnafu {
                path: metadata_outdir.as_ref(),
            })?;
        tokio::fs::create_dir_all(targets_outdir.as_ref())
            .await
            .context(error::CacheDirectoryCreateSnafu {
                path: targets_outdir.as_ref(),
            })?;

        // Fetch targets and save them to the outdir
        if let Some(target_list) = targets_subset {
            for raw_name in target_list {
                let target_name = TargetName::new(raw_name.as_ref())?;
                self.cache_target(&targets_outdir, &target_name).await?;
            }
        } else {
            let targets = &self.targets.signed.targets_map();
            for target_name in targets.keys() {
                self.cache_target(&targets_outdir, target_name).await?;
            }
        }

        // Cache all metadata
        self.cache_metadata_impl(&metadata_outdir).await?;

        if cache_root_chain {
            self.cache_root_chain(&metadata_outdir).await?;
        }
        Ok(())
    }

    /// Cache only a repository's metadata files (snapshot, targets, timestamp), including any
    /// delegated targets metadata.  The cached files will be saved to the local filesystem.
    ///
    /// * `metadata_outdir` is the directory where cached metadata files will be saved.
    /// * `cache_root_chain` specifies whether or not we will cache all versions of `root.json`.
    pub async fn cache_metadata<P>(&self, metadata_outdir: P, cache_root_chain: bool) -> Result<()>
    where
        P: AsRef<Path>,
    {
        // Create the output directory if it does not exist.
        tokio::fs::create_dir_all(metadata_outdir.as_ref())
            .await
            .context(error::CacheDirectoryCreateSnafu {
                path: metadata_outdir.as_ref(),
            })?;

        self.cache_metadata_impl(&metadata_outdir).await?;

        if cache_root_chain {
            self.cache_root_chain(metadata_outdir).await?;
        }
        Ok(())
    }

    /// Cache repository metadata files, including delegated targets metadata
    async fn cache_metadata_impl<P>(&self, metadata_outdir: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        self.cache_file_from_transport(
            self.snapshot_filename().as_str(),
            self.max_snapshot_size()?
                .unwrap_or(self.limits.max_snapshot_size),
            "timestamp.json",
            &metadata_outdir,
        )
        .await?;
        self.cache_file_from_transport(
            self.targets_filename().as_str(),
            self.limits.max_targets_size,
            "max_targets_size argument",
            &metadata_outdir,
        )
        .await?;
        self.cache_file_from_transport(
            "timestamp.json",
            self.limits.max_timestamp_size,
            "max_timestamp_size argument",
            &metadata_outdir,
        )
        .await?;

        for name in self.targets.signed.role_names() {
            if let Some(filename) = self.delegated_filename(name) {
                self.cache_file_from_transport(
                    filename.as_str(),
                    self.limits.max_targets_size,
                    "max_targets_size argument",
                    &metadata_outdir,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Cache all versions of root.json less than or equal to the current version.
    async fn cache_root_chain<P>(&self, outdir: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        for ver in (1..=self.root.signed.version.get()).rev() {
            let root_json_filename = format!("{ver}.root.json");
            self.cache_file_from_transport(
                root_json_filename.as_str(),
                self.limits.max_root_size,
                "max_root_size argument",
                &outdir,
            )
            .await?;
        }
        Ok(())
    }

    /// Prepends the version number to the snapshot.json filename if using consistent snapshot mode.
    fn snapshot_filename(&self) -> String {
        if self.root.signed.consistent_snapshot {
            format!("{}.snapshot.json", self.snapshot.signed.version)
        } else {
            "snapshot.json".to_owned()
        }
    }

    /// Prepends the version number to the targets.json filename if using consistent snapshot mode.
    fn targets_filename(&self) -> String {
        if self.root.signed.consistent_snapshot {
            format!("{}.targets.json", self.targets.signed.version)
        } else {
            "targets.json".to_owned()
        }
    }

    /// Prepends the version number to the role.json filename if using consistent snapshot mode.
    fn delegated_filename(&self, name: &str) -> Option<String> {
        if self.root.signed.consistent_snapshot {
            Some(format!(
                "{}.{}.json",
                self.snapshot
                    .signed
                    .meta
                    .get(&format!("{name}.json"))?
                    .version,
                encode_filename(name)
            ))
        } else {
            Some(format!("{}.json", encode_filename(name)))
        }
    }

    /// Copies a file using `Transport` to `outdir`.
    async fn cache_file_from_transport<P: AsRef<Path>>(
        &self,
        filename: &str,
        max_size: u64,
        max_size_specifier: &'static str,
        outdir: P,
    ) -> Result<()> {
        let url = self
            .metadata_base_url
            .join(filename)
            .with_context(|_| error::JoinUrlSnafu {
                path: filename,
                url: self.metadata_base_url.clone(),
            })?;
        let stream = fetch_max_size(
            self.transport.as_ref(),
            url.clone(),
            max_size,
            max_size_specifier,
        )
        .await?;
        let outpath = outdir.as_ref().join(filename);
        let mut file = tokio::fs::File::create(&outpath).await.with_context(|_| {
            error::CacheFileWriteSnafu {
                path: outpath.clone(),
            }
        })?;
        let root_file_data = stream
            .into_vec()
            .await
            .context(error::TransportSnafu { url })?;
        file.write_all(&root_file_data)
            .await
            .context(error::CacheFileWriteSnafu { path: outpath })
    }

    /// Saves a signed target to the specified `outdir`. Retains the digest-prepended filename if
    /// consistent snapshots are used.
    async fn cache_target<P: AsRef<Path>>(&self, outdir: P, name: &TargetName) -> Result<()> {
        self.save_target(
            name,
            outdir,
            if self.consistent_snapshot {
                Prefix::Digest
            } else {
                Prefix::None
            },
        )
        .await
    }

    /// Gets the max size of the snapshot.json file as specified by the timestamp file.
    fn max_snapshot_size(&self) -> Result<Option<u64>> {
        let snapshot_meta =
            self.timestamp()
                .signed
                .meta
                .get("snapshot.json")
                .context(error::MetaMissingSnafu {
                    file: "snapshot.json",
                    role: RoleType::Timestamp,
                })?;
        Ok(snapshot_meta.length)
    }

    /// Prepends the target digest to the name if using consistent snapshots. Returns both the
    /// digest and the filename.
    pub(crate) fn target_digest_and_filename(
        &self,
        target: &Target,
        name: &TargetName,
    ) -> (Vec<u8>, String) {
        let sha256 = &target.hashes.sha256.clone().into_vec();
        if self.consistent_snapshot {
            (
                sha256.clone(),
                format!("{}.{}", hex::encode(sha256), name.resolved()),
            )
        } else {
            (sha256.clone(), name.resolved().to_owned())
        }
    }

    /// Fetches the signed target using `Transport`. Aborts with error if the fetched target is
    /// larger than its signed size.
    pub(crate) async fn fetch_target(
        &self,
        target: &Target,
        digest: &[u8],
        filename: &str,
    ) -> Result<BoxStream<'static, Result<Bytes>>> {
        let url = self
            .targets_base_url
            .join(filename)
            .with_context(|_| error::JoinUrlSnafu {
                path: filename,
                url: self.targets_base_url.clone(),
            })?;
        Ok(fetch_sha256(
            self.transport.as_ref(),
            url.clone(),
            target.length,
            "targets.json",
            digest,
        )
        .await?
        .context(error::TransportSnafu { url })
        .boxed())
    }
}

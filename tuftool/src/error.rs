// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Not really worried about the memory penalty of large enum variants here
#![allow(clippy::large_enum_variant)]
#![allow(clippy::default_trait_access)]

use snafu::{Backtrace, Snafu};
use std::path::PathBuf;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub(crate) enum Error {
    #[snafu(display("Failed to run {}: {}", command_str, source))]
    CommandExec {
        command_str: String,
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Command {} failed with {}", command_str, status))]
    CommandStatus {
        command_str: String,
        status: std::process::ExitStatus,
        backtrace: Backtrace,
    },

    #[snafu(display("Command {} output is not valid UTF-8: {}", command_str, source))]
    CommandUtf8 {
        command_str: String,
        source: std::string::FromUtf8Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Cannot determine current directory: {}", source))]
    CurrentDir {
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Date argument '{}' is invalid: {}", input, msg))]
    DateArgInvalid { input: String, msg: &'static str },

    #[snafu(display(
        "Date argument had count '{}' that failed to parse as integer: {}",
        input,
        source
    ))]
    DateArgCount {
        input: String,
        source: std::num::ParseIntError,
    },

    #[snafu(display("Failed to create directory '{}': {}", path.display(), source))]
    DirCreate {
        path: PathBuf,
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Couldn't find {}", role))]
    DelegateeNotFound {
        role: String,
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Invalid delegation structure"))]
    DelegationStructure {
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display(
        "Failed to create a Repository Editor with root.json '{}': {}",
        path.display(),
        source
    ))]
    EditorCreate {
        path: PathBuf,
        source: tough::error::Error,
    },

    #[snafu(display("Failed to create a RepositoryEditor from an existing repo with root.json '{}': {}", path.display(), source))]
    EditorFromRepo {
        path: PathBuf,
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to open {}: {}", path.display(), source))]
    FileOpen {
        path: PathBuf,
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to parse {}: {}", path.display(), source))]
    FileParseJson {
        path: PathBuf,
        source: serde_json::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to copy {} to {}: {}", source.file.path().display(), path.display(), source.error))]
    FilePersist {
        path: PathBuf,
        source: tempfile::PersistError,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to create temporary file in {}: {}", path.display(), source))]
    FileTempCreate {
        path: PathBuf,
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to write to {}: {}", path.display(), source))]
    FileWrite {
        path: PathBuf,
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to write to {}: {}", path.display(), source))]
    FileWriteJson {
        path: PathBuf,
        source: serde_json::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to initialize global thread pool: {}", source))]
    InitializeThreadPool {
        source: rayon::ThreadPoolBuildError,
        backtrace: Backtrace,
    },

    #[snafu(display("Duplicate key ID: {}", key_id))]
    KeyDuplicate {
        key_id: String,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to calculate key ID: {}", source))]
    KeyId {
        #[snafu(backtrace)]
        source: tough::schema::Error,
    },

    #[snafu(display("Unable to parse keypair: {}", source))]
    KeyPairParse {
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Unable to parse keypair: {}", source))]
    KeyPairFromKeySource {
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        backtrace: Backtrace,
    },

    #[snafu(display(
        "Failed to symlink target data from '{}' to '{}': {}",
        indir.display(),
        outdir.display(),
        source
    ))]
    LinkTargets {
        indir: PathBuf,
        outdir: PathBuf,
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Unable to initialize logger: {}", source))]
    Logger { source: simplelog::TermLogError },

    #[snafu(display("Unable to load incoming metadata: {}", source))]
    LoadMetadata {
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Metadata error: {}", source))]
    Metadata {
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Unable to determine file name from path: '{}'", path.display()))]
    NoFileName { path: PathBuf, backtrace: Backtrace },

    #[snafu(display("Failed to open file {}: {}", path.display(), source))]
    OpenFile {
        path: PathBuf,
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to open trusted root metadata file {}: {}", path.display(), source))]
    OpenRoot {
        path: PathBuf,
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Path {} does not have a parent", path.display()))]
    PathParent { path: PathBuf, backtrace: Backtrace },

    #[snafu(display("Path {} is not valid UTF-8", path.display()))]
    PathUtf8 { path: PathBuf, backtrace: Backtrace },

    #[snafu(display("Failed to load repository: {}", source))]
    RepoLoad {
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to copy from response: {}", source))]
    ReqwestCopy {
        source: reqwest::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Error making request: {}", source))]
    ReqwestGet {
        source: reqwest::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to sign repository: {}", source))]
    SignRepo {
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Unable to sign roles: {:?}", roles))]
    SignRoles {
        roles: Vec<String>,
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Unable to remove signed roles: {:?}", roles))]
    SignRolesRemove { roles: Vec<String> },

    #[snafu(display("Failed to sign '{}': {}", path.display(), source))]
    SignRoot {
        path: PathBuf,
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Unable to create Target from path '{}': {}", path.display(), source))]
    TargetFromPath {
        path: PathBuf,
        source: tough::schema::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to add targets from directory '{}': {}", dir.display(), source))]
    TargetsFromDir {
        dir: PathBuf,
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Target not found: {}", target))]
    TargetNotFound {
        target: String,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to create temporary directory: {}", source))]
    TempDir {
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Unrecognized URL scheme \"{}\"", scheme))]
    UnrecognizedScheme {
        scheme: String,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to parse URL \"{}\": {}", url, source))]
    UrlParse {
        url: String,
        source: url::ParseError,
        backtrace: Backtrace,
    },

    #[snafu(display("Version number overflow"))]
    VersionOverflow { backtrace: Backtrace },

    #[snafu(display("Version number is zero"))]
    VersionZero { backtrace: Backtrace },

    #[snafu(display("Failed to walk directory tree '{}': {}", directory.display(), source))]
    WalkDir {
        directory: PathBuf,
        source: walkdir::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed write: {}", source))]
    WriteKeySource {
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed writing repo data to disk at '{}': {}", directory.display(), source))]
    WriteRepo {
        directory: PathBuf,
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Unable to write roles: {:?}", roles))]
    WriteRoles {
        roles: Vec<String>,
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed writing target data to disk: {}", source))]
    WriteTarget {
        source: std::io::Error,
        backtrace: Backtrace,
    },
}

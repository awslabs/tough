// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

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

    #[snafu(display("Failed to copy {} to {}: {}", src.display(), dst.display(), source))]
    FileCopy {
        src: PathBuf,
        dst: PathBuf,
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to create {}: {}", path.display(), source))]
    FileCreate {
        path: PathBuf,
        source: std::io::Error,
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

    #[snafu(display("Failed to read {}: {}", path.display(), source))]
    FileRead {
        path: PathBuf,
        source: std::io::Error,
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

    #[snafu(display("Unable to match any of the provided keys with root.json"))]
    KeysNotFoundInRoot { backtrace: Backtrace },

    #[snafu(display("Metadata error: {}", source))]
    Metadata {
        source: tough::error::Error,
        backtrace: Backtrace,
    },

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

    #[snafu(display("Path {} is not valid UTF-8", path.display()))]
    PathUtf8 { path: PathBuf, backtrace: Backtrace },

    #[snafu(display("Path {} does not have a parent", path.display()))]
    PathParent { path: PathBuf, backtrace: Backtrace },

    // the source error is zero-sized with a fixed message, no sense in displaying it
    #[snafu(display("Path {} is not within {}", path.display(), base.display()))]
    Prefix {
        path: PathBuf,
        base: PathBuf,
        source: std::path::StripPrefixError,
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

    #[snafu(display("Failed to sign message"))]
    Sign {
        source: tough::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to serialize role for signing: {}", source))]
    SignJson {
        source: serde_json::Error,
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

    #[snafu(display("Unrecognized or invalid public key"))]
    UnrecognizedKey { backtrace: Backtrace },

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

    #[snafu(display("Failed to walk directory tree: {}", source))]
    WalkDir {
        source: walkdir::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed write: {}", source))]
    WriteKeySource {
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed writing target data to disk: {}", source))]
    WriteTarget {
        source: std::io::Error,
        backtrace: Backtrace,
    },
}

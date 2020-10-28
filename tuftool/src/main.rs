// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

#![deny(rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    // Identifiers like Command::Create are clearer than Self::Create regardless of context
    clippy::use_self,
    // Caused by interacting with tough::schema::*._extra
    clippy::used_underscore_binding,
)]

mod add_key_role;
mod add_role;
mod common;
mod create;
mod create_role;
mod datetime;
mod download;
mod error;
mod remove_key_role;
mod remove_role;
mod root;
mod source;
mod update;
mod update_targets;

use crate::error::Result;
use rayon::prelude::*;
use simplelog::{ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use snafu::{ErrorCompat, OptionExt, ResultExt};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use structopt::StructOpt;
use tempfile::NamedTempFile;
use tough::schema::Target;
use walkdir::WalkDir;

static SPEC_VERSION: &str = "1.0.0";

/// This wrapper enables global options and initializes the logger before running any subcommands.
#[derive(StructOpt)]
struct Program {
    /// Set logging verbosity [trace|debug|info|warn|error]
    #[structopt(
        name = "log-level",
        short = "l",
        long = "log-level",
        default_value = "info"
    )]
    log_level: LevelFilter,
    #[structopt(subcommand)]
    cmd: Command,
}

impl Program {
    fn run(self) -> Result<()> {
        TermLogger::init(
            self.log_level,
            ConfigBuilder::new()
                .add_filter_allow_str("tuftool")
                .add_filter_allow_str("tough")
                .build(),
            TerminalMode::Mixed,
        )
        .context(error::Logger)?;
        self.cmd.run()
    }
}

#[derive(Debug, StructOpt)]
enum Command {
    /// Create a TUF repository
    Create(create::CreateArgs),
    /// Download a TUF repository's resources
    Download(download::DownloadArgs),
    /// Update a TUF repository's metadata and optionally add targets
    Update(Box<update::UpdateArgs>),
    /// Manipulate a root.json metadata file
    Root(root::Command),
    /// Delegation Commands
    Delegation(Delegation),
}

impl Command {
    fn run(self) -> Result<()> {
        match self {
            Command::Create(args) => args.run(),
            Command::Root(root_subcommand) => root_subcommand.run(),
            Command::Download(args) => args.run(),
            Command::Update(args) => args.run(),
            Command::Delegation(cmd) => cmd.run(),
        }
    }
}

fn load_file<T>(path: &Path) -> Result<T>
where
    for<'de> T: serde::Deserialize<'de>,
{
    serde_json::from_reader(File::open(path).context(error::FileOpen { path })?)
        .context(error::FileParseJson { path })
}

fn write_file<T>(path: &Path, json: &T) -> Result<()>
where
    T: serde::Serialize,
{
    // Use `tempfile::NamedTempFile::persist` to perform an atomic file write.
    let parent = path.parent().context(error::PathParent { path })?;
    let mut writer =
        NamedTempFile::new_in(parent).context(error::FileTempCreate { path: parent })?;
    serde_json::to_writer_pretty(&mut writer, json).context(error::FileWriteJson { path })?;
    writer.write_all(b"\n").context(error::FileWrite { path })?;
    writer.persist(path).context(error::FilePersist { path })?;
    Ok(())
}

// Walk the directory specified, building a map of filename to Target structs.
// Hashing of the targets is done in parallel
fn build_targets<P>(indir: P, follow_links: bool) -> Result<HashMap<String, Target>>
where
    P: AsRef<Path>,
{
    let indir = indir.as_ref();
    WalkDir::new(indir)
        .follow_links(follow_links)
        .into_iter()
        .par_bridge()
        .filter_map(|entry| match entry {
            Ok(entry) => {
                if entry.file_type().is_file() {
                    Some(process_target(entry.path()))
                } else {
                    None
                }
            }
            Err(err) => Some(Err(err).context(error::WalkDir { directory: indir })),
        })
        .collect()
}

fn process_target(path: &Path) -> Result<(String, Target)> {
    // Build a Target from the path given. If it is not a file, this will fail
    let target = Target::from_path(path).context(error::TargetFromPath { path })?;

    // Get the file name as a string
    let target_name = path
        .file_name()
        .context(error::NoFileName { path })?
        .to_str()
        .context(error::PathUtf8 { path })?
        .to_owned();
    Ok((target_name, target))
}

fn main() -> ! {
    std::process::exit(match Program::from_args().run() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{}", err);
            if let Some(var) = std::env::var_os("RUST_BACKTRACE") {
                if var != "0" {
                    if let Some(backtrace) = err.backtrace() {
                        eprintln!("\n{:?}", backtrace);
                    }
                }
            }
            1
        }
    })
}

#[derive(StructOpt, Debug)]
struct Delegation {
    /// The signing role
    #[structopt(long = "signing-role", required = true)]
    role: String,

    #[structopt(subcommand)]
    cmd: DelegationCommand,
}

impl Delegation {
    fn run(self) -> Result<()> {
        self.cmd.run(&self.role)
    }
}

#[derive(Debug, StructOpt)]
enum DelegationCommand {
    /// Creates a delegated role
    CreateRole(Box<create_role::CreateRoleArgs>),
    /// Add delegated role
    AddRole(Box<add_role::AddRoleArgs>),
    /// Update Delegated targets
    UpdateDelegatedTargets(Box<update_targets::UpdateTargetsArgs>),
    /// Add a key to a delegated role
    AddKey(Box<add_key_role::AddKeyArgs>),
    /// Remove a key from a delegated role
    RemoveKey(Box<remove_key_role::RemoveKeyArgs>),
    /// Remove a role
    Remove(Box<remove_role::RemoveRoleArgs>),
}

impl DelegationCommand {
    fn run(self, role: &str) -> Result<()> {
        match self {
            DelegationCommand::CreateRole(args) => args.run(role),
            DelegationCommand::AddRole(args) => args.run(role),
            DelegationCommand::UpdateDelegatedTargets(args) => args.run(role),
            DelegationCommand::AddKey(args) => args.run(role),
            DelegationCommand::RemoveKey(args) => args.run(role),
            DelegationCommand::Remove(args) => args.run(role),
        }
    }
}

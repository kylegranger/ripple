//! Utilities for setting up and tearing down Ripple node instances.

use std::{io, path::PathBuf};

use crate::setup::constants::{RIPPLE_WORK_DIR, ZIGGURAT_DIR};

pub mod config;
pub mod constants;
pub mod node;
pub mod testnet;

pub fn build_ripple_work_path() -> io::Result<PathBuf> {
    Ok(home::home_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "couldn't find home directory"))?
        .join(ZIGGURAT_DIR)
        .join(RIPPLE_WORK_DIR))
}

#![forbid(unsafe_code)]
//! FSView: disk, filesystem and storage-pool manager for Proxmox VE hosts.
//!
//! Two processes share this crate:
//! * `fsview serve`  – unprivileged web server (UI, auth, sessions, API)
//! * `fsview helper` – root helper on a Unix socket that runs a fixed
//!   allow-list of typed operations and enforces every safety rule itself.

pub mod auth;
pub mod bootcheck;
pub mod config;
pub mod events;
pub mod helper;
pub mod helperclient;
pub mod inventory;
pub mod netutil;
pub mod proto;
pub mod runner;
pub mod smart;
pub mod store;
pub mod web;

/// Build version (set by the release workflow via FSVIEW_VERSION).
pub const VERSION: &str = match option_env!("FSVIEW_VERSION") {
    Some(v) => v,
    None => concat!("v", env!("CARGO_PKG_VERSION"), "-dev"),
};

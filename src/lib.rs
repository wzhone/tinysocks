//! Library surface for the proxy runtime and protocol helpers.
//!
//! The binary target owns CLI parsing and platform installation. This library
//! keeps proxy behavior testable without invoking privileged service operations.

pub mod auth;
pub mod config;
pub mod handler;
pub mod http;
pub mod io_timeout;
pub mod protocol;
pub mod server;
pub mod stats;

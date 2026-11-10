//! `rcptx` — smart asynchronous SMTP reconnaissance & deliverability
//! probing as a library.
//!
//! The binary in `src/main.rs` is a thin wrapper around these modules:
//!
//! - [`cli`] — argument parsing, validation and input resolution
//! - [`dns`] — MX / SPF / DMARC recon and provider detection
//! - [`presets`] — built-in local-part dictionaries
//! - [`scanner`] — the probing orchestrator (sessions, failover, retries)
//! - [`smtp`] — the low-level async client and reply parser
//! - [`output`] — table / json / jsonl / csv formatting
//! - [`update`] — GitHub Releases update checks

#![forbid(unsafe_code)]

pub mod cli;
pub mod dns;
pub mod output;
pub mod presets;
pub mod scanner;
pub mod smtp;
pub mod update;

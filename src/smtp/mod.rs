//! Low-level asynchronous SMTP client: TCP + optional TLS transport, the
//! `Banner → EHLO → STARTTLS → EHLO → MAIL FROM → RCPT TO → RSET → QUIT`
//! state machine, and RFC 3463-aware reply parsing.

pub mod client;
pub mod parser;

pub use client::{SmtpConnection, SmtpError, Stage};
pub use parser::SmtpReply;

use clap::ValueEnum;

/// STARTTLS negotiation policy.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum StarttlsMode {
    /// Upgrade to TLS when the server offers STARTTLS, continue in plain text otherwise.
    #[default]
    Opportunistic,
    /// Abort the connection when STARTTLS is not offered or fails.
    Required,
    /// Never negotiate TLS.
    Disabled,
}

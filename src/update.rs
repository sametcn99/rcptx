//! Update checks against GitHub Releases.
//!
//! `rcptx check-update` (or the `--check-update` flag) asks the GitHub
//! API for the latest release of [`GITHUB_REPO`] and compares it with the
//! running version. The HTTPS request reuses the crate's pure-Rust rustls
//! stack — no extra HTTP client dependency.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::smtp::client::tls_client_config;

/// GitHub repository that releases are checked against.
pub const GITHUB_REPO: &str = "sametcn99/rcptx";
/// Permalink to the latest release page.
pub const RELEASES_URL: &str = "https://github.com/sametcn99/rcptx/releases/latest";
/// Repository home page.
pub const REPO_URL: &str = "https://github.com/sametcn99/rcptx";

const API_HOST: &str = "api.github.com";
/// Maximum accepted response size (the release payload is a few KB).
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Version of the running binary.
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// User agent sent to the GitHub API (it rejects requests without one).
pub const USER_AGENT: &str = concat!("rcptx/", env!("CARGO_PKG_VERSION"));

/// Outcome of an update check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateInfo {
    /// Version of the running binary.
    pub current: String,
    /// Latest released version (leading `v` stripped).
    pub latest: String,
    /// True when the latest release is newer than the running version.
    pub update_available: bool,
    /// HTML URL of the latest release.
    pub release_url: String,
    /// True when the latest release is flagged as a prerelease.
    pub prerelease: bool,
}

/// Check the latest GitHub release for this repository.
///
/// # Errors
///
/// Returns an error on network failure, TLS failure, a non-200 API response,
/// an unparsable payload, or when `timeout` elapses.
pub async fn check_for_update(timeout: Duration) -> Result<UpdateInfo> {
    tokio::time::timeout(timeout, async {
        let path = format!("/repos/{GITHUB_REPO}/releases/latest");
        let body = https_get_json(API_HOST, &path).await?;
        parse_release_payload(&body)
    })
    .await
    .map_err(|_| anyhow!("update check timed after {}s", timeout.as_secs()))?
}

/// Extract update information from a GitHub release API payload.
///
/// # Errors
///
/// Returns an error when the body is not valid JSON or has no `tag_name`.
pub fn parse_release_payload(body: &str) -> Result<UpdateInfo> {
    let value: serde_json::Value =
        serde_json::from_str(body).context("parsing the GitHub release payload")?;
    let tag = value["tag_name"]
        .as_str()
        .context("the release payload is missing tag_name")?;
    let latest = normalize_version(tag).to_string();
    Ok(UpdateInfo {
        current: CURRENT_VERSION.to_string(),
        update_available: is_newer(&latest, CURRENT_VERSION),
        release_url: value["html_url"]
            .as_str()
            .unwrap_or(RELEASES_URL)
            .to_string(),
        prerelease: value["prerelease"].as_bool().unwrap_or(false),
        latest,
    })
}

async fn https_get_json(host: &str, path: &str) -> Result<String> {
    let connector = TlsConnector::from(tls_client_config(false));
    let tcp = TcpStream::connect((host, 443_u16))
        .await
        .with_context(|| format!("connecting to {host}:443"))?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| anyhow!("invalid host name: {e}"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .context("the TLS handshake with the GitHub API failed")?;

    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {USER_AGENT}\r\n\
         Accept: application/vnd.github+json\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n\
         \r\n"
    );
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;

    let mut raw = Vec::new();
    tls.take(MAX_RESPONSE_BYTES).read_to_end(&mut raw).await?;
    parse_http_response(&raw)
}

/// Split an HTTP/1.1 response into its body, verifying the status code and
/// transparently decoding chunked transfer encoding.
///
/// # Errors
///
/// Returns an error for malformed responses or non-200 status codes.
pub fn parse_http_response(raw: &[u8]) -> Result<String> {
    let separator = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("the HTTP response has no header/body separator")?;
    let head = String::from_utf8_lossy(&raw[..separator + 4]).into_owned();
    let body = &raw[separator + 4..];

    let status_line = head.lines().next().unwrap_or_default();
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|token| token.parse().ok())
        .context("the HTTP status line is malformed")?;
    if code != 200 {
        let reason = head
            .lines()
            .nth(1)
            .and_then(|line| line.strip_prefix('{'))
            .map(|rest| format!(" ({})", rest.trim_end_matches('}')));
        bail!(
            "the GitHub API returned HTTP {code}{}",
            reason.unwrap_or_default()
        );
    }

    let decoded = if head.to_lowercase().contains("transfer-encoding: chunked") {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    Ok(String::from_utf8_lossy(&decoded).into_owned())
}

fn dechunk(body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut position = 0;
    loop {
        let line_end = find_crlf(&body[position..])
            .with_context(|| "the chunked response ended unexpectedly")?;
        let size_text = std::str::from_utf8(&body[position..position + line_end])
            .context("the chunk size line is not valid UTF-8")?;
        let size_text = size_text.split(';').next().unwrap_or("0").trim();
        let size =
            usize::from_str_radix(size_text, 16).context("the chunk size is not valid hex")?;
        position += line_end + 2;
        if size == 0 {
            break;
        }
        if position + size > body.len() {
            bail!("the chunked response is truncated");
        }
        out.extend_from_slice(&body[position..position + size]);
        position += size + 2; // skip the trailing CRLF after each chunk
    }
    Ok(out)
}

fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

/// True when `latest` is strictly newer than `current`. The comparison is
/// numeric per dotted component; `v` prefixes and `-pre`/`+build` suffixes
/// are ignored (`0.10.0` is newer than `0.9.9`).
pub fn is_newer(latest: &str, current: &str) -> bool {
    version_key(latest) > version_key(current)
}

/// Strip a leading `v`/`V` from a version tag.
pub fn normalize_version(tag: &str) -> &str {
    tag.trim().trim_start_matches(['v', 'V'])
}

fn version_key(version: &str) -> Vec<u64> {
    normalize_version(version)
        .split(['-', '+'])
        .next()
        .unwrap_or_default()
        .split('.')
        .map(|part| part.split('-').next().unwrap_or(part).parse().unwrap_or(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_versions_are_detected_numerically() {
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(is_newer("0.10.0", "0.9.9")); // numeric, not lexicographic
        assert!(is_newer("0.1.1", "0.1.0"));
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("1.2.3", "1.2.2-beta.1"));
    }

    #[test]
    fn equal_or_older_versions_are_not_newer() {
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(!is_newer("0.1.0-alpha", "0.1.0"));
    }

    #[test]
    fn version_tags_are_normalized() {
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_version(" 1.2.3 "), "1.2.3");
        assert_eq!(normalize_version("1.2.3"), "1.2.3");
    }

    #[test]
    fn release_payload_is_parsed() {
        let body = r#"{"tag_name":"v9.9.9","html_url":"https://github.com/sametcn99/rcptx/releases/tag/v9.9.9","prerelease":false}"#;
        let info = parse_release_payload(body).unwrap();
        assert_eq!(info.latest, "9.9.9");
        assert!(info.update_available);
        assert!(!info.prerelease);
        assert_eq!(
            info.release_url,
            "https://github.com/sametcn99/rcptx/releases/tag/v9.9.9"
        );
        assert_eq!(info.current, CURRENT_VERSION);
    }

    #[test]
    fn release_payload_requires_tag_name() {
        assert!(parse_release_payload("{}").is_err());
        assert!(parse_release_payload("not json").is_err());
    }

    #[test]
    fn http_response_with_body_is_parsed() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"tag_name\":\"v0.1.0\"}";
        assert_eq!(
            parse_http_response(raw).unwrap(),
            "{\"tag_name\":\"v0.1.0\"}"
        );
    }

    #[test]
    fn chunked_http_response_is_decoded() {
        // Two chunks: "hello " (6) and "world" (5), then the terminating chunk.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(raw).unwrap(), "hello world");
    }

    #[test]
    fn http_errors_are_surfaced() {
        assert!(parse_http_response(b"HTTP/1.1 404 Not Found\r\n\r\n").is_err());
        assert!(parse_http_response(b"garbage").is_err());
    }

    #[test]
    fn user_agent_contains_version() {
        assert!(USER_AGENT.starts_with("rcptx/"));
        assert!(USER_AGENT.ends_with(CURRENT_VERSION));
    }
}

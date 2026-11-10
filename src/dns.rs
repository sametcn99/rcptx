//! Async DNS: MX resolution (sorted by preference), custom resolver support,
//! SPF/DMARC TXT pre-checks, and mail-infrastructure provider detection.

use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use serde::Serialize;

/// One MX record: an exchange hostname plus its routing preference.
#[derive(Debug, Clone, Serialize)]
pub struct MxEntry {
    /// Lower value = higher priority.
    pub preference: u16,
    /// Exchange hostname, lower-cased, without the trailing dot. `.` marks a
    /// null MX (RFC 7505 — domain does not accept mail).
    pub exchange: String,
}

/// Security posture of a domain's email infrastructure.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DomainSecurity {
    /// The `v=spf1` TXT record on the apex, when present.
    pub spf: Option<String>,
    /// The `v=DMARC1` TXT record on `_dmarc.<domain>`, when present.
    pub dmarc: Option<String>,
}

/// Wrapper around a hickory async resolver, optionally pinned to a custom
/// nameserver (`--dns-server`).
pub struct DnsResolver {
    inner: TokioAsyncResolver,
}

impl DnsResolver {
    /// Build a resolver. With no server given this uses the system
    /// configuration; otherwise queries go to `<ip>:53` over UDP with TCP
    /// fallback handled by hickory.
    ///
    /// # Errors
    ///
    /// Returns an error when the system DNS configuration cannot be read or
    /// the custom configuration is rejected.
    pub fn new(server: Option<IpAddr>) -> Result<Self> {
        let inner = match server {
            Some(ip) => {
                let group = NameServerConfigGroup::from_ips_clear(&[ip], 53, true);
                let config =
                    ResolverConfig::from_parts(None, Vec::new(), group);
                TokioAsyncResolver::tokio(config, ResolverOpts::default())
            }
            None => TokioAsyncResolver::tokio_from_system_conf()
                .context("failed to load the system DNS configuration")?,
        };
        Ok(Self { inner })
    }

    /// Resolve MX records for a domain, sorted by ascending preference.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails (NXDOMAIN, SERVFAIL, timeout, …).
    pub async fn mx(&self, domain: &str) -> Result<Vec<MxEntry>> {
        let lookup = self
            .inner
            .mx_lookup(domain)
            .await
            .map_err(|e| anyhow!("MX lookup for {domain} failed: {e}"))?;
        let mut entries: Vec<MxEntry> = lookup
            .iter()
            .map(|record| {
                // Normalize casing/trailing dot, but keep "." intact for null MX (RFC 7505).
                let raw = record.exchange().to_string().to_lowercase();
                let exchange = if raw == "." { raw } else { raw.trim_end_matches('.').to_string() };
                MxEntry {
                    preference: record.preference(),
                    exchange,
                }
            })
            .collect();
        entries.sort_by_key(|entry| entry.preference);
        Ok(entries)
    }

    /// Fetch all TXT strings published at a name. Never fails: an empty vec is
    /// returned for missing records so callers can treat DNS softly here.
    pub async fn txt(&self, name: &str) -> Vec<String> {
        match self.inner.txt_lookup(name).await {
            Ok(lookup) => lookup
                .iter()
                .flat_map(|record| {
                    record
                        .txt_data()
                        .iter()
                        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                        .collect::<Vec<_>>()
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// SPF + DMARC posture for a domain (both lookups run concurrently).
    pub async fn security(&self, domain: &str) -> DomainSecurity {
        let dmarc_name = format!("_dmarc.{domain}");
        let (apex_txt, dmarc_txt) = futures::join!(self.txt(domain), self.txt(&dmarc_name));
        DomainSecurity {
            spf: apex_txt.into_iter().find(|s| s.to_ascii_lowercase().starts_with("v=spf1")),
            dmarc: dmarc_txt.into_iter().find(|s| s.to_ascii_lowercase().starts_with("v=dmarc1")),
        }
    }
}

/// Guess the receiving mail platform from MX hostnames and SPF includes.
pub fn detect_provider(mx: &[MxEntry], spf: Option<&str>) -> Option<&'static str> {
    let mut haystack = mx
        .iter()
        .map(|entry| entry.exchange.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(spf) = spf {
        haystack.push(' ');
        haystack.push_str(spf);
    }
    let haystack = haystack.to_ascii_lowercase();

    const PROVIDERS: &[(&str, &str)] = &[
        ("protection.outlook.com", "Microsoft 365 / Exchange Online"),
        ("outlook.com", "Microsoft 365 / Exchange Online"),
        ("google.com", "Google Workspace"),
        ("googlemail.com", "Google Workspace"),
        ("ppe-hosted.com", "Proofpoint"),
        ("pphosted.com", "Proofpoint"),
        ("ppops.net", "Proofpoint"),
        ("mimecast.com", "Mimecast"),
        ("barracudanetworks.com", "Barracuda"),
        ("messagelabs.com", "Symantec MessageLabs"),
        ("zoho", "Zoho Mail"),
        ("mx.cloudflare.net", "Cloudflare Email Routing"),
        ("icloud.com", "Apple iCloud Mail"),
        ("yandex", "Yandex 360"),
        ("amazonaws.com", "Amazon WorkMail / SES"),
        ("ovh.net", "OVHcloud"),
        ("secureserver.net", "GoDaddy"),
    ];

    PROVIDERS
        .iter()
        .find_map(|(needle, name)| haystack.contains(needle).then_some(*name))
}

//! Async DNS: MX resolution (sorted by preference), custom resolver support,
//! SPF/DMARC TXT pre-checks, and mail-infrastructure provider detection.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
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
    /// configuration; otherwise queries go to `<ip>:53` over UDP. Custom
    /// servers get aggressive timeouts (2s, single attempt) so a bad
    /// `--dns-server` fails fast instead of stalling every domain.
    ///
    /// # Errors
    ///
    /// Returns an error when the system DNS configuration cannot be read or
    /// the custom configuration is rejected.
    pub fn new(server: Option<IpAddr>) -> Result<Self> {
        let inner = match server {
            Some(ip) => {
                let group = NameServerConfigGroup::from_ips_clear(&[ip], 53, true);
                let config = ResolverConfig::from_parts(None, Vec::new(), group);
                let mut options = ResolverOpts::default();
                options.timeout = Duration::from_secs(2);
                options.attempts = 1;
                TokioAsyncResolver::tokio(config, options)
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
                let exchange = if raw == "." {
                    raw
                } else {
                    raw.trim_end_matches('.').to_string()
                };
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
    /// Best-effort: the whole pre-flight is bounded to 5 seconds and returns
    /// empty posture on timeout — a slow resolver must never stall a scan.
    pub async fn security(&self, domain: &str) -> DomainSecurity {
        let lookup = async {
            let dmarc_name = format!("_dmarc.{domain}");
            let (apex_txt, dmarc_txt) = futures::join!(self.txt(domain), self.txt(&dmarc_name));
            DomainSecurity {
                spf: apex_txt
                    .into_iter()
                    .find(|s| s.to_ascii_lowercase().starts_with("v=spf1")),
                dmarc: dmarc_txt
                    .into_iter()
                    .find(|s| s.to_ascii_lowercase().starts_with("v=dmarc1")),
            }
        };
        tokio::time::timeout(Duration::from_secs(5), lookup)
            .await
            .unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn mx(preference: u16, exchange: &str) -> MxEntry {
        MxEntry {
            preference,
            exchange: exchange.to_string(),
        }
    }

    #[test]
    fn providers_are_detected_from_mx_hosts() {
        assert_eq!(
            detect_provider(&[mx(5, "aspmx.l.google.com")], None),
            Some("Google Workspace")
        );
        assert_eq!(
            detect_provider(&[mx(10, "example-com.mail.protection.outlook.com")], None),
            Some("Microsoft 365 / Exchange Online")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx.pphosted.com")], None),
            Some("Proofpoint")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx.ppe-hosted.com")], None),
            Some("Proofpoint")
        );
        assert_eq!(
            detect_provider(&[mx(10, "eu.mimecast.com")], None),
            Some("Mimecast")
        );
        assert_eq!(
            detect_provider(&[mx(10, "route1.mx.cloudflare.net")], None),
            Some("Cloudflare Email Routing")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx01.mail.icloud.com")], None),
            Some("Apple iCloud Mail")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx.yandex.ru")], None),
            Some("Yandex 360")
        );
    }

    #[test]
    fn providers_are_detected_from_spf_includes() {
        assert_eq!(
            detect_provider(&[], Some("v=spf1 include:spf.protection.outlook.com -all")),
            Some("Microsoft 365 / Exchange Online")
        );
        assert_eq!(
            detect_provider(
                &[mx(10, "mx1.example.com")],
                Some("v=spf1 include:_spf.google.com ~all")
            ),
            Some("Google Workspace")
        );
    }

    #[test]
    fn unknown_infrastructure_stays_unknown() {
        assert_eq!(
            detect_provider(
                &[mx(10, "mx.example.com")],
                Some("v=spf1 ip4:10.0.0.1 -all")
            ),
            None
        );
        assert_eq!(detect_provider(&[], None), None);
        assert_eq!(detect_provider(&[mx(0, ".")], None), None);
    }
}

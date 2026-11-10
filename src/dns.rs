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

    // Fingerprints are matched against MX hostnames plus the SPF record, in
    // order — put more specific needles before generic ones within a vendor.
    const PROVIDERS: &[(&str, &str)] = &[
        // Secure email gateways / email security services
        ("ppe-hosted.com", "Proofpoint"),
        ("pphosted.com", "Proofpoint"),
        ("ppops.net", "Proofpoint"),
        ("mimecast.com", "Mimecast"),
        ("barracudanetworks.com", "Barracuda Email Security"),
        ("cudamail.com", "Barracuda Email Security"),
        ("iphmx.com", "Cisco Email Security (IronPort)"),
        ("messagelabs.com", "Symantec / Broadcom MessageLabs"),
        ("trendmicro.com", "Trend Micro Email Security"),
        ("spamd.one", "Sophos Email"),
        ("vadesecure.com", "Vade for Email"),
        ("hornetsecurity.com", "Hornetsecurity 365 Total Protection"),
        ("abnormal.ai", "Abnormal Security"),
        ("avanan.com", "Check Point Harmony Email (Avanan)"),
        ("checkpoint.com", "Check Point Harmony Email (Avanan)"),
        ("appriver.com", "AppRiver"),
        ("mailassure.com", "N-able Mail Assure (SpamExperts)"),
        ("spamexperts.com", "N-able Mail Assure (SpamExperts)"),
        ("reflexion.net", "Reflexion Email Security"),
        ("retarus.com", "Retarus"),
        ("retarus.de", "Retarus"),
        // Cloud productivity suites
        ("protection.outlook.com", "Microsoft 365 / Exchange Online"),
        ("outlook.com", "Microsoft 365 / Exchange Online"),
        ("google.com", "Google Workspace"),
        ("googlemail.com", "Google Workspace"),
        ("psmtp.com", "Google Postini (legacy Message Security)"),
        ("zoho", "Zoho Mail"),
        ("icloud.com", "Apple iCloud Mail"),
        ("yandex", "Yandex 360"),
        ("amazonaws.com", "Amazon WorkMail / SES"),
        ("aliyun", "Alibaba Cloud Mail (Qiye)"),
        ("qq.com", "QQ Mail / Tencent Exmail"),
        ("163.com", "NetEase Mail"),
        ("126.com", "NetEase Mail"),
        ("naver.com", "Naver Mail"),
        // Consumer & shared-hosting mail
        ("messagingengine.com", "Fastmail"),
        ("protonmail.ch", "Proton Mail"),
        ("protonmail.com", "Proton Mail"),
        ("gmx.net", "GMX"),
        ("gmx.com", "GMX"),
        ("emailsrvr.com", "Rackspace Email"),
        ("secureserver.net", "GoDaddy"),
        ("privateemail.com", "Namecheap Private Email"),
        ("hostinger.com", "Hostinger Email"),
        ("hostgator.com", "HostGator"),
        ("bluehost.com", "Bluehost"),
        ("rzone.de", "STRATO AG"),
        ("kundenserver.de", "IONOS by 1&1"),
        ("perfora.net", "IONOS by 1&1"),
        ("ovh.net", "OVHcloud"),
        ("mail.gandi.net", "Gandi Mail"),
        ("oxcs.net", "Open-Xchange (hosted)"),
        // Forwarding services
        ("mx.cloudflare.net", "Cloudflare Email Routing"),
        ("improvmx.com", "ImprovMX (forwarding)"),
        ("forwardemail.net", "Forward Email (forwarding)"),
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

    #[test]
    fn security_gateway_providers_are_detected() {
        assert_eq!(
            detect_provider(&[mx(10, "mx1.ess.barracudanetworks.com")], None),
            Some("Barracuda Email Security")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx1.cudamail.com")], None),
            Some("Barracuda Email Security")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx1.iphmx.com")], None),
            Some("Cisco Email Security (IronPort)")
        );
        assert_eq!(
            detect_provider(&[mx(10, "a3456.hes.trendmicro.com")], None),
            Some("Trend Micro Email Security")
        );
        assert_eq!(
            detect_provider(&[mx(10, "eu1.spamd.one")], None),
            Some("Sophos Email")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx1.vadesecure.com")], None),
            Some("Vade for Email")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx1.hornetsecurity.com")], None),
            Some("Hornetsecurity 365 Total Protection")
        );
        assert_eq!(
            detect_provider(&[mx(10, "inbound.abnormal.ai")], None),
            Some("Abnormal Security")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx.avanan.com")], None),
            Some("Check Point Harmony Email (Avanan)")
        );
        assert_eq!(
            detect_provider(&[mx(10, "gw.checkpoint.com")], None),
            Some("Check Point Harmony Email (Avanan)")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mail.appriver.com")], None),
            Some("AppRiver")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx1.mailassure.com")], None),
            Some("N-able Mail Assure (SpamExperts)")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx.spamexperts.com")], None),
            Some("N-able Mail Assure (SpamExperts)")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx.reflexion.net")], None),
            Some("Reflexion Email Security")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx1.retarus.de")], None),
            Some("Retarus")
        );
    }

    #[test]
    fn regional_and_hosting_providers_are_detected() {
        assert_eq!(
            detect_provider(&[mx(10, "in1-smtp.messagingengine.com")], None),
            Some("Fastmail")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mail.protonmail.ch")], None),
            Some("Proton Mail")
        );
        assert_eq!(detect_provider(&[mx(10, "gmx.net")], None), Some("GMX"));
        assert_eq!(
            detect_provider(&[mx(10, "mx1.emailsrvr.com")], None),
            Some("Rackspace Email")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx01.privateemail.com")], None),
            Some("Namecheap Private Email")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx1.hostinger.com")], None),
            Some("Hostinger Email")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx1.hostgator.com")], None),
            Some("HostGator")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx01.rzone.de")], None),
            Some("STRATO AG")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx00.kundenserver.de")], None),
            Some("IONOS by 1&1")
        );
        assert_eq!(
            detect_provider(&[mx(10, "smtp.perfora.net")], None),
            Some("IONOS by 1&1")
        );
        assert_eq!(
            detect_provider(&[mx(10, "spool.mail.gandi.net")], None),
            Some("Gandi Mail")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mxbiz1.qq.com")], None),
            Some("QQ Mail / Tencent Exmail")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx.qiye.aliyun.com")], None),
            Some("Alibaba Cloud Mail (Qiye)")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx.naver.com")], None),
            Some("Naver Mail")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx1.psmtp.com")], None),
            Some("Google Postini (legacy Message Security)")
        );
    }

    #[test]
    fn forwarding_services_are_detected() {
        assert_eq!(
            detect_provider(&[mx(10, "mx1.improvmx.com")], None),
            Some("ImprovMX (forwarding)")
        );
        assert_eq!(
            detect_provider(&[mx(10, "mx1.forwardemail.net")], None),
            Some("Forward Email (forwarding)")
        );
    }

    #[test]
    fn more_specific_fingerprints_win_within_a_vendor() {
        // Both needles map to the same vendor, but the specific one matches first.
        assert_eq!(
            detect_provider(&[mx(10, "example-com.mail.protection.outlook.com")], None),
            Some("Microsoft 365 / Exchange Online")
        );
    }
}

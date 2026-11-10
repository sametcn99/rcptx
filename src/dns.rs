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

/// One fingerprint needle and the mail platform it identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct ProviderFingerprint {
    /// Coarse grouping shown by `rcptx providers`.
    pub category: &'static str,
    /// Lowercase substring matched against MX hostnames and the SPF record.
    pub needle: &'static str,
    /// Platform name reported on a match.
    pub provider: &'static str,
}

/// The built-in provider fingerprint table, grouped by category. Entries are
/// matched in order — more specific needles must precede generic ones within
/// a vendor (`protection.outlook.com` before `outlook.com`).
pub const PROVIDER_FINGERPRINTS: &[ProviderFingerprint] = &[
    // Secure email gateways / email security services
    ProviderFingerprint {
        category: "gateway",
        needle: "ppe-hosted.com",
        provider: "Proofpoint",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "pphosted.com",
        provider: "Proofpoint",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "ppops.net",
        provider: "Proofpoint",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "mimecast.com",
        provider: "Mimecast",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "barracudanetworks.com",
        provider: "Barracuda Email Security",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "cudamail.com",
        provider: "Barracuda Email Security",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "iphmx.com",
        provider: "Cisco Email Security (IronPort)",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "messagelabs.com",
        provider: "Symantec / Broadcom MessageLabs",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "trendmicro.com",
        provider: "Trend Micro Email Security",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "spamd.one",
        provider: "Sophos Email",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "vadesecure.com",
        provider: "Vade for Email",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "hornetsecurity.com",
        provider: "Hornetsecurity 365 Total Protection",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "abnormal.ai",
        provider: "Abnormal Security",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "avanan.com",
        provider: "Check Point Harmony Email (Avanan)",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "checkpoint.com",
        provider: "Check Point Harmony Email (Avanan)",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "appriver.com",
        provider: "AppRiver",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "mailassure.com",
        provider: "N-able Mail Assure (SpamExperts)",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "spamexperts.com",
        provider: "N-able Mail Assure (SpamExperts)",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "reflexion.net",
        provider: "Reflexion Email Security",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "retarus.com",
        provider: "Retarus",
    },
    ProviderFingerprint {
        category: "gateway",
        needle: "retarus.de",
        provider: "Retarus",
    },
    // Cloud productivity suites
    ProviderFingerprint {
        category: "cloud suite",
        needle: "protection.outlook.com",
        provider: "Microsoft 365 / Exchange Online",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "outlook.com",
        provider: "Microsoft 365 / Exchange Online",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "google.com",
        provider: "Google Workspace",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "googlemail.com",
        provider: "Google Workspace",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "psmtp.com",
        provider: "Google Postini (legacy Message Security)",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "zoho",
        provider: "Zoho Mail",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "icloud.com",
        provider: "Apple iCloud Mail",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "yandex",
        provider: "Yandex 360",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "amazonaws.com",
        provider: "Amazon WorkMail / SES",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "aliyun",
        provider: "Alibaba Cloud Mail (Qiye)",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "qq.com",
        provider: "QQ Mail / Tencent Exmail",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "163.com",
        provider: "NetEase Mail",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "126.com",
        provider: "NetEase Mail",
    },
    ProviderFingerprint {
        category: "cloud suite",
        needle: "naver.com",
        provider: "Naver Mail",
    },
    // Consumer & shared-hosting mail
    ProviderFingerprint {
        category: "hosting",
        needle: "messagingengine.com",
        provider: "Fastmail",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "protonmail.ch",
        provider: "Proton Mail",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "protonmail.com",
        provider: "Proton Mail",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "gmx.net",
        provider: "GMX",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "gmx.com",
        provider: "GMX",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "emailsrvr.com",
        provider: "Rackspace Email",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "secureserver.net",
        provider: "GoDaddy",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "privateemail.com",
        provider: "Namecheap Private Email",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "hostinger.com",
        provider: "Hostinger Email",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "hostgator.com",
        provider: "HostGator",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "bluehost.com",
        provider: "Bluehost",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "rzone.de",
        provider: "STRATO AG",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "kundenserver.de",
        provider: "IONOS by 1&1",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "perfora.net",
        provider: "IONOS by 1&1",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "ovh.net",
        provider: "OVHcloud",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "mail.gandi.net",
        provider: "Gandi Mail",
    },
    ProviderFingerprint {
        category: "hosting",
        needle: "oxcs.net",
        provider: "Open-Xchange (hosted)",
    },
    // Forwarding services
    ProviderFingerprint {
        category: "forwarding",
        needle: "mx.cloudflare.net",
        provider: "Cloudflare Email Routing",
    },
    ProviderFingerprint {
        category: "forwarding",
        needle: "improvmx.com",
        provider: "ImprovMX (forwarding)",
    },
    ProviderFingerprint {
        category: "forwarding",
        needle: "forwardemail.net",
        provider: "Forward Email (forwarding)",
    },
];

/// Filter the fingerprint table by category, case-insensitively. Returns
/// `None` when the category does not exist so callers can list valid ones.
pub fn fingerprints_by_category(filter: &str) -> Option<Vec<ProviderFingerprint>> {
    let filtered: Vec<ProviderFingerprint> = PROVIDER_FINGERPRINTS
        .iter()
        .copied()
        .filter(|fingerprint| fingerprint.category.eq_ignore_ascii_case(filter))
        .collect();
    (!filtered.is_empty()).then_some(filtered)
}

/// Where a provider fingerprint matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchSource {
    /// The needle matched inside this MX hostname.
    MxHost(String),
    /// The needle matched inside the SPF record.
    SpfRecord,
}

/// A provider detection result with provenance, for fingerprint debugging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMatch {
    /// Platform name that matched.
    pub name: &'static str,
    /// The needle that matched.
    pub needle: &'static str,
    /// Where the needle matched.
    pub source: MatchSource,
}

impl ProviderMatch {
    /// One-line human-readable provenance, e.g.
    /// `needle "google.com" matched MX host aspmx.l.google.com`.
    pub fn describe(&self) -> String {
        match &self.source {
            MatchSource::MxHost(host) => {
                format!("needle {:?} matched MX host {}", self.needle, host)
            }
            MatchSource::SpfRecord => format!("needle {:?} matched the SPF record", self.needle),
        }
    }
}

/// Guess the receiving mail platform from MX hostnames and SPF includes.
pub fn detect_provider(mx: &[MxEntry], spf: Option<&str>) -> Option<&'static str> {
    detect_provider_detail(mx, spf).map(|matched| matched.name)
}

/// Like [`detect_provider`], but reports *which* needle matched and where —
/// the provenance surfaced by `rcptx mx -v` and the scan-report notes.
pub fn detect_provider_detail(mx: &[MxEntry], spf: Option<&str>) -> Option<ProviderMatch> {
    for fingerprint in PROVIDER_FINGERPRINTS {
        for entry in mx {
            if entry.exchange.to_lowercase().contains(fingerprint.needle) {
                return Some(ProviderMatch {
                    name: fingerprint.provider,
                    needle: fingerprint.needle,
                    source: MatchSource::MxHost(entry.exchange.clone()),
                });
            }
        }
        if let Some(spf) = spf
            && spf.to_lowercase().contains(fingerprint.needle)
        {
            return Some(ProviderMatch {
                name: fingerprint.provider,
                needle: fingerprint.needle,
                source: MatchSource::SpfRecord,
            });
        }
    }
    None
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

    #[test]
    fn provider_detail_reports_needle_and_mx_host() {
        let detail = detect_provider_detail(&[mx(5, "aspmx.l.google.com")], None).unwrap();
        assert_eq!(detail.name, "Google Workspace");
        assert_eq!(detail.needle, "google.com");
        assert_eq!(
            detail.source,
            MatchSource::MxHost("aspmx.l.google.com".to_string())
        );
        assert_eq!(
            detail.describe(),
            r#"needle "google.com" matched MX host aspmx.l.google.com"#
        );
    }

    #[test]
    fn provider_detail_reports_spf_source() {
        let detail =
            detect_provider_detail(&[], Some("v=spf1 include:spf.protection.outlook.com -all"))
                .unwrap();
        assert_eq!(detail.name, "Microsoft 365 / Exchange Online");
        assert_eq!(detail.needle, "protection.outlook.com");
        assert_eq!(detail.source, MatchSource::SpfRecord);
        assert!(detail.describe().contains("SPF record"));
    }

    #[test]
    fn detail_agrees_with_simple_detection() {
        let cases: [(Vec<MxEntry>, Option<&str>); 4] = [
            (vec![mx(10, "mx.pphosted.com")], None),
            (vec![mx(10, "in1-smtp.messagingengine.com")], None),
            (
                vec![mx(10, "mx1.example.com")],
                Some("v=spf1 include:_spf.google.com ~all"),
            ),
            (vec![mx(10, "mx1.example.com")], None),
        ];
        for (entries, spf) in cases {
            assert_eq!(
                detect_provider(&entries, spf),
                detect_provider_detail(&entries, spf).map(|m| m.name)
            );
        }
    }

    #[test]
    fn fingerprint_table_is_sane() {
        assert!(PROVIDER_FINGERPRINTS.len() > 50);
        let mut needles: Vec<&str> = PROVIDER_FINGERPRINTS.iter().map(|fp| fp.needle).collect();
        let total = needles.len();
        needles.sort_unstable();
        needles.dedup();
        assert_eq!(needles.len(), total, "fingerprint needles must be unique");
        for fingerprint in PROVIDER_FINGERPRINTS {
            assert!(!fingerprint.needle.is_empty(), "empty needle");
            assert!(
                !fingerprint.provider.is_empty(),
                "empty provider for {}",
                fingerprint.needle
            );
            assert!(
                !fingerprint.category.is_empty(),
                "empty category for {}",
                fingerprint.needle
            );
            assert_eq!(
                fingerprint.needle,
                fingerprint.needle.to_lowercase(),
                "{} must be lowercase",
                fingerprint.needle
            );
            assert!(
                !fingerprint.needle.contains(char::is_whitespace),
                "{} must not contain whitespace",
                fingerprint.needle
            );
        }
    }

    #[test]
    fn specific_needles_precede_generic_ones_in_the_table() {
        let position = |needle: &str| {
            PROVIDER_FINGERPRINTS
                .iter()
                .position(|fp| fp.needle == needle)
                .unwrap_or_else(|| panic!("{needle} missing from the table"))
        };
        assert!(position("protection.outlook.com") < position("outlook.com"));
        assert!(position("protonmail.ch") < position("protonmail.com"));
        assert!(position("avanan.com") < position("checkpoint.com"));
    }

    #[test]
    fn category_filter_is_case_insensitive_and_exclusive() {
        let gateways = fingerprints_by_category("gateway").unwrap();
        assert!(!gateways.is_empty());
        assert!(gateways.iter().all(|fp| fp.category == "gateway"));

        let suites = fingerprints_by_category("Cloud Suite").unwrap();
        assert!(suites.iter().all(|fp| fp.category == "cloud suite"));
        assert!(suites.len() < PROVIDER_FINGERPRINTS.len());

        for category in ["hosting", "FORWARDING"] {
            let filtered = fingerprints_by_category(category).unwrap();
            assert!(
                filtered
                    .iter()
                    .all(|fp| fp.category.eq_ignore_ascii_case(category))
            );
        }
    }

    #[test]
    fn category_filter_rejects_unknown_categories() {
        assert!(fingerprints_by_category("bogus").is_none());
        assert!(fingerprints_by_category("").is_none());
    }

    #[test]
    fn categories_are_listed_in_the_table() {
        let mut categories: Vec<&str> =
            PROVIDER_FINGERPRINTS.iter().map(|fp| fp.category).collect();
        categories.sort_unstable();
        categories.dedup();
        assert_eq!(
            categories,
            ["cloud suite", "forwarding", "gateway", "hosting"]
        );
    }
}

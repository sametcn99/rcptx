//! CLI definition (clap derive), validation, and resolution of raw arguments
//! into a fully-prepared [`ResolvedConfig`] for the scanner.

use std::io::Read as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser, Subcommand};

use crate::output::Format;
use crate::presets;
use crate::smtp::StarttlsMode;

/// Smart asynchronous SMTP reconnaissance: probe recipient validity, MX
/// posture and catch-all behaviour without sending email.
#[derive(Parser, Debug)]
#[command(name = "smtp-probe", version, about, long_about = None)]
pub struct Cli {
    /// Subcommand (optional). Default behaviour is the full probe.
    #[command(subcommand)]
    pub command: Option<Command>,

    // -----------------------------------------------------------------
    // Target & input
    // -----------------------------------------------------------------
    /// Single target domain (e.g. example.com). May be given per-env.
    #[arg(short, long, value_name = "DOMAIN", env = "SMTP_PROBE_DOMAIN")]
    pub domain: Option<String>,

    /// File with target domains or email addresses, one per line ('#' comments allowed).
    #[arg(short = 'D', long, value_name = "PATH")]
    pub domains_file: Option<PathBuf>,

    /// Read target domains or full email addresses from standard input.
    #[arg(long)]
    pub stdin: bool,

    /// Comma-separated built-in presets: hr, general, support, tech, executive, all.
    #[arg(short, long, value_name = "PRESETS", default_value = presets::DEFAULT_SPEC)]
    pub preset: String,

    /// Custom local-part wordlist file, merged with the presets.
    #[arg(short, long, value_name = "PATH")]
    pub wordlist: Option<PathBuf>,

    /// Ignore built-in presets; probe only --wordlist / --local-parts.
    #[arg(long)]
    pub no_presets: bool,

    /// Comma-separated inline local-parts (e.g. hr,cto,careers).
    #[arg(short = 'l', long, value_name = "PARTS")]
    pub local_parts: Option<String>,

    // -----------------------------------------------------------------
    // SMTP & network
    // -----------------------------------------------------------------
    /// Envelope sender used in MAIL FROM. May be given per-env.
    #[arg(
        short = 'f',
        long,
        value_name = "EMAIL",
        default_value = "probe@example.com",
        env = "SMTP_PROBE_MAIL_FROM"
    )]
    pub mail_from: String,

    /// Generate a plausible random sender instead of --mail-from. Optionally pin the domain: --auto-mail-from=mydomain.tld.
    #[arg(long, value_name = "DOMAIN", num_args = 0..=1, require_equals = true, default_missing_value = "")]
    pub auto_mail_from: Option<String>,

    /// Custom EHLO hostname (default: system hostname).
    #[arg(long, value_name = "HOSTNAME")]
    pub ehlo: Option<String>,

    /// Randomize the EHLO hostname on every connection.
    #[arg(long)]
    pub random_ehlo: bool,

    /// SMTP port: 25 (default), 587 (submission) or 465 (implicit TLS).
    #[arg(long, default_value_t = 25, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: u16,

    /// Skip MX lookup and probe this mail server directly (IP or hostname).
    #[arg(long, value_name = "HOST")]
    pub mx_host: Option<String>,

    /// Explicitly keep MX failover (the default behaviour).
    #[arg(long)]
    pub mx_failover: bool,

    /// Disable failover to lower-priority MX servers.
    #[arg(long)]
    pub no_mx_failover: bool,

    /// STARTTLS policy: opportunistic (default), required, or disabled.
    #[arg(long, value_enum, default_value = "opportunistic")]
    pub starttls: StarttlsMode,

    /// Skip TLS certificate verification (legacy / self-signed servers).
    #[arg(long)]
    pub insecure: bool,

    /// Custom DNS resolver IP (e.g. 1.1.1.1, 8.8.8.8); default: system. May be given per-env.
    #[arg(long, value_name = "IP", env = "SMTP_PROBE_DNS_SERVER", global = true)]
    pub dns_server: Option<IpAddr>,

    // -----------------------------------------------------------------
    // Scanning, rate-limiting & anti-blocking
    // -----------------------------------------------------------------
    /// Max concurrent SMTP connections per domain.
    #[arg(short, long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=64))]
    pub concurrency: u16,

    /// RCPT probes per SMTP session (via RSET) before reconnecting. Use 1 to force a fresh connection per probe.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(1..=10_000))]
    pub max_rcpt_per_conn: u32,

    /// Base delay between probes, in milliseconds.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(0..=3_600_000))]
    pub delay_ms: u64,

    /// Random +/- jitter added to --delay-ms to mimic natural traffic, in milliseconds.
    #[arg(long, default_value_t = 150, value_parser = clap::value_parser!(u64).range(0..=3_600_000))]
    pub jitter_ms: u64,

    /// Connect/read/write timeout, in seconds.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=600))]
    pub timeout: u64,

    /// Random UUID catch-all probes before scanning candidates. 0 disables.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(0..=16))]
    pub catch_all_probes: u16,

    /// Skip candidate scanning when the domain is confirmed catch-all.
    #[arg(long)]
    pub stop_on_catch_all: bool,

    /// Retries for 4xx (greylist) responses. 0 disables.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(0..=16))]
    pub retry_greylist: u16,

    /// Wait before retrying greylisted candidates, in seconds.
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(0..=3_600))]
    pub retry_delay: u64,

    /// Check GitHub Releases for a newer version before running (never fatal).
    #[arg(long, global = true)]
    pub check_update: bool,

    // -----------------------------------------------------------------
    // Filtering & output
    // -----------------------------------------------------------------
    /// Write output to a file instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE", global = true)]
    pub output: Option<PathBuf>,

    /// Output format: table (default), json, jsonl or csv.
    #[arg(long, value_enum, default_value = "table", global = true)]
    pub format: Format,

    /// Only output Accepted (and AcceptedCatchAll) results.
    #[arg(long)]
    pub only_accepted: bool,

    /// Suppress the banner, progress bars and non-essential logs.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Verbose: -v shows the raw SMTP transcript, -vv debug logs, -vvv trace.
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,
}

/// Optional subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// DNS reconnaissance only (MX, SPF, DMARC, provider guess) — no SMTP probing.
    Mx {
        /// Domain to inspect (e.g. example.com).
        domain: String,
    },
    /// Check GitHub Releases for a newer version and exit.
    CheckUpdate,
}

/// Fully-resolved runtime configuration handed to the scanner.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    /// Target domains (deduplicated, lower-cased).
    pub targets: Vec<String>,
    /// Candidate local-parts in probe order.
    pub local_parts: Vec<String>,
    /// Envelope sender for MAIL FROM.
    pub mail_from: String,
    /// EHLO identity base.
    pub ehlo: String,
    /// Randomize EHLO per connection.
    pub random_ehlo: bool,
    /// SMTP port.
    pub port: u16,
    /// Direct mail-server override.
    pub mx_host: Option<String>,
    /// Fall back to lower-priority MX servers.
    pub mx_failover: bool,
    /// STARTTLS policy.
    pub starttls: StarttlsMode,
    /// Skip TLS verification.
    pub insecure: bool,
    /// Custom DNS server.
    pub dns_server: Option<IpAddr>,
    /// Concurrent connections per domain.
    pub concurrency: usize,
    /// RCPT probes per session before reconnecting.
    pub max_rcpt_per_conn: usize,
    /// Base inter-probe delay.
    pub delay_ms: u64,
    /// Jitter around the base delay.
    pub jitter_ms: u64,
    /// Per-operation timeout.
    pub timeout: Duration,
    /// Random catch-all probes.
    pub catch_all_probes: usize,
    /// Skip candidates on confirmed catch-all domains.
    pub stop_on_catch_all: bool,
    /// Greylist retry rounds.
    pub retry_greylist: usize,
    /// Delay before greylist retries.
    pub retry_delay: Duration,
    /// Output format.
    pub format: Format,
    /// Keep only accepted results in the output.
    pub only_accepted: bool,
}

impl Cli {
    /// Cross-field validation that clap cannot express declaratively.
    ///
    /// # Errors
    ///
    /// Returns a user-facing error message when the combination of flags is
    /// unusable.
    pub fn validate(&self) -> Result<()> {
        if self.command.is_none() {
            let has_target = self.domain.is_some() || self.domains_file.is_some() || self.stdin;
            if !has_target {
                bail!(
                    "no target given: pass -d/--domain <DOMAIN>, -D/--domains-file <PATH> or --stdin"
                );
            }
        }

        if !self.no_presets {
            presets::resolve(&self.preset)?;
        } else if self.wordlist.is_none() && self.local_parts.is_none() {
            bail!("--no-presets requires --wordlist <PATH> and/or --local-parts <PARTS>");
        }

        if self.catch_all_probes == 0 && self.stop_on_catch_all {
            bail!("--stop-on-catch-all requires --catch-all-probes > 0");
        }
        if self.mx_failover && self.no_mx_failover {
            bail!("--mx-failover and --no-mx-failover are mutually exclusive");
        }
        if self.port == 465 && self.starttls != StarttlsMode::Disabled {
            tracing::debug!("port 465 uses implicit TLS; the --starttls setting is ignored");
        }
        Ok(())
    }

    /// MX failover is on unless explicitly disabled (default: true).
    pub fn effective_mx_failover(&self) -> bool {
        !self.no_mx_failover
    }

    /// Quiet is forced when the user asked for it, when stdout is piped, or
    /// when a machine-readable format is written to stdout — progress bars and
    /// banners must never pollute machine output.
    pub fn effective_quiet(&self) -> bool {
        if self.quiet {
            return true;
        }
        if self.output.is_some() {
            return false;
        }
        let stdout_piped = !console::Term::stdout().features().is_attended();
        stdout_piped || self.format != Format::Table
    }

    /// Read all inputs (targets, wordlists, stdin) and prepare the runtime
    /// configuration. Pure CLI parsing stays in clap; all I/O lives here.
    ///
    /// # Errors
    ///
    /// Returns an error for unreadable files or an unusable configuration.
    pub fn resolve(&self) -> Result<ResolvedConfig> {
        let mut targets: Vec<String> = Vec::new();
        if let Some(domain) = &self.domain {
            normalize_target(domain, &mut targets);
        }
        if let Some(path) = &self.domains_file {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("reading domains file {}", path.display()))?;
            for line in content.lines() {
                normalize_target(line, &mut targets);
            }
        }
        if self.stdin {
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .context("reading targets from stdin")?;
            for line in buffer.lines() {
                normalize_target(line, &mut targets);
            }
        }
        if self.command.is_none() && targets.is_empty() {
            bail!("no valid target domains were provided");
        }

        let mut local_parts: Vec<String> = Vec::new();
        if !self.no_presets {
            local_parts.extend(presets::resolve(&self.preset)?);
        }
        if let Some(path) = &self.wordlist {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("reading wordlist {}", path.display()))?;
            for line in content.lines() {
                push_local_part(line, &mut local_parts);
            }
        }
        if let Some(inline) = &self.local_parts {
            for part in inline.split(',') {
                push_local_part(part, &mut local_parts);
            }
        }
        if self.command.is_none() && local_parts.is_empty() {
            bail!(
                "no candidate local-parts to probe (presets / wordlist / --local-parts produced nothing)"
            );
        }

        let mail_from = match &self.auto_mail_from {
            Some(spec) if spec.is_empty() => generate_mail_from(None),
            Some(spec) => generate_mail_from(Some(spec.as_str())),
            None => self.mail_from.trim().to_lowercase(),
        };
        if !mail_from.contains('@') {
            bail!("invalid envelope sender {mail_from:?}: expected user@domain");
        }

        let ehlo = sanitize_hostname(&self.ehlo.clone().unwrap_or_else(system_hostname));

        Ok(ResolvedConfig {
            targets,
            local_parts,
            mail_from,
            ehlo,
            random_ehlo: self.random_ehlo,
            port: self.port,
            mx_host: self.mx_host.as_deref().map(normalize_host),
            mx_failover: self.effective_mx_failover(),
            starttls: self.starttls,
            insecure: self.insecure,
            dns_server: self.dns_server,
            concurrency: usize::from(self.concurrency),
            max_rcpt_per_conn: self.max_rcpt_per_conn as usize,
            delay_ms: self.delay_ms,
            jitter_ms: self.jitter_ms,
            timeout: Duration::from_secs(self.timeout),
            catch_all_probes: usize::from(self.catch_all_probes),
            stop_on_catch_all: self.stop_on_catch_all,
            retry_greylist: usize::from(self.retry_greylist),
            retry_delay: Duration::from_secs(self.retry_delay),
            format: self.format,
            only_accepted: self.only_accepted,
        })
    }
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_lowercase()
}

fn push_local_part(raw: &str, out: &mut Vec<String>) {
    let trimmed = raw.trim();
    let part = trimmed
        .rsplit_once('@')
        .map(|(local, _)| local)
        .unwrap_or(trimmed);
    let part = part
        .trim()
        .trim_matches(|c| c == '<' || c == '>')
        .to_lowercase();
    if !part.is_empty() && !part.starts_with('#') && !out.contains(&part) {
        out.push(part);
    }
}

fn normalize_target(raw: &str, out: &mut Vec<String>) {
    let trimmed = raw.trim().trim_start_matches("mailto:");
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }
    let domain = trimmed.rsplit_once('@').map(|(_, d)| d).unwrap_or(trimmed);
    let domain = domain
        .trim()
        .trim_matches(|c| c == '<' || c == '>' || c == '.')
        .to_lowercase();
    if domain.is_empty() || domain.chars().any(char::is_whitespace) {
        return;
    }
    if !out.contains(&domain) {
        out.push(domain);
    }
}

fn system_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .map(|h| h.to_lowercase())
        .unwrap_or_else(|_| "smtp-probe.local".to_string())
}

fn sanitize_hostname(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "smtp-probe.local".to_string()
    } else {
        cleaned
    }
}

const SENDER_FIRST_NAMES: &[&str] = &[
    "james",
    "mary",
    "john",
    "patricia",
    "robert",
    "jennifer",
    "michael",
    "linda",
    "david",
    "elizabeth",
    "william",
    "barbara",
    "richard",
    "susan",
    "joseph",
    "jessica",
];
const SENDER_LAST_NAMES: &[&str] = &[
    "smith",
    "johnson",
    "williams",
    "brown",
    "jones",
    "garcia",
    "miller",
    "davis",
    "rodriguez",
    "martinez",
    "wilson",
    "anderson",
    "taylor",
    "thomas",
    "moore",
    "jackson",
];
const SENDER_DOMAINS: &[&str] = &[
    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "hotmail.com",
    "icloud.com",
];

fn generate_mail_from(domain: Option<&str>) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let first = SENDER_FIRST_NAMES[rng.gen_range(0..SENDER_FIRST_NAMES.len())];
    let last = SENDER_LAST_NAMES[rng.gen_range(0..SENDER_LAST_NAMES.len())];
    let number: u32 = rng.gen_range(10..9_999);
    let domain = domain
        .unwrap_or(SENDER_DOMAINS[rng.gen_range(0..SENDER_DOMAINS.len())])
        .trim_start_matches('@')
        .to_lowercase();
    format!("{first}.{last}{number:04}@{domain}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("smtp-probe").chain(args.iter().copied()))
            .expect("cli parses")
    }

    #[test]
    fn validation_requires_a_target() {
        assert!(parse(&[]).validate().is_err());
    }

    #[test]
    fn validation_accepts_a_domain() {
        parse(&["-d", "example.com"]).validate().unwrap();
    }

    #[test]
    fn validation_rejects_unknown_presets() {
        assert!(
            parse(&["-d", "example.com", "-p", "bogus"])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn no_presets_requires_other_sources() {
        assert!(
            parse(&["-d", "example.com", "--no-presets"])
                .validate()
                .is_err()
        );
        parse(&["-d", "example.com", "--no-presets", "-l", "hr"])
            .validate()
            .unwrap();
    }

    #[test]
    fn stop_on_catch_all_requires_catch_all_probes() {
        assert!(
            parse(&[
                "-d",
                "example.com",
                "--stop-on-catch-all",
                "--catch-all-probes",
                "0"
            ])
            .validate()
            .is_err()
        );
    }

    #[test]
    fn mx_failover_flags_conflict() {
        assert!(
            parse(&["-d", "example.com", "--mx-failover", "--no-mx-failover"])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn targets_are_normalized_and_deduplicated() {
        let mut targets: Vec<String> = Vec::new();
        normalize_target("Example.COM.", &mut targets);
        normalize_target("user@example.com", &mut targets);
        normalize_target("  # a comment", &mut targets);
        normalize_target("", &mut targets);
        normalize_target("example.com", &mut targets);
        assert_eq!(targets, ["example.com"]);

        let mut mailto: Vec<String> = Vec::new();
        normalize_target("mailto:hr@corp.example", &mut mailto);
        assert_eq!(mailto, ["corp.example"]);
    }

    #[test]
    fn local_parts_are_normalized_and_deduplicated() {
        let mut parts: Vec<String> = Vec::new();
        push_local_part(" HR ", &mut parts);
        push_local_part("hr", &mut parts);
        push_local_part("<CTO>@x", &mut parts);
        push_local_part("# comment", &mut parts);
        push_local_part("", &mut parts);
        assert_eq!(parts, ["hr", "cto"]);
    }

    #[test]
    fn hostnames_are_sanitized() {
        // Case is preserved for user-provided EHLO names; the system hostname
        // is lower-cased separately in system_hostname().
        assert_eq!(sanitize_hostname("LAPTOP 01\n"), "LAPTOP-01-");
        assert_eq!(sanitize_hostname(""), "smtp-probe.local");
        assert_eq!(sanitize_hostname("probe.example.com"), "probe.example.com");
    }

    #[test]
    fn generated_senders_are_plausible() {
        let address = generate_mail_from(None);
        assert_eq!(address.matches('@').count(), 1);
        assert!(address.split('@').next().unwrap().contains('.'));
        let pinned = generate_mail_from(Some("@MyDomain.IO"));
        assert!(pinned.ends_with("@mydomain.io"));
        assert!(pinned.starts_with(|c: char| c.is_ascii_alphabetic()));
    }

    #[test]
    fn resolve_reads_files_and_merges_candidates() {
        let dir = std::env::temp_dir();
        let domains_file = dir.join(format!(
            "smtp-probe-test-domains-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let wordlist = dir.join(format!(
            "smtp-probe-test-words-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::write(&domains_file, "# targets\nExample.COM\nhr@corp.example\n\n").unwrap();
        std::fs::write(&wordlist, "\n# roles\nCEO\nCFO\nJobs\n").unwrap();

        let cli = parse(&[
            "-D",
            domains_file.to_str().unwrap(),
            "-w",
            wordlist.to_str().unwrap(),
            "-l",
            "jobs,cto",
            "-p",
            "support",
            "--mx-host",
            "MX.Example.COM.",
            "--catch-all-probes",
            "3",
        ]);
        cli.validate().unwrap();
        let config = cli.resolve().unwrap();

        assert_eq!(config.targets, ["example.com", "corp.example"]);
        // Presets come first, then the wordlist and inline parts, all deduped.
        assert_eq!(config.local_parts.first().unwrap(), "support");
        assert!(config.local_parts.contains(&"ceo".to_string()));
        assert!(config.local_parts.contains(&"cfo".to_string()));
        assert_eq!(
            config.local_parts.iter().filter(|p| p == &"jobs").count(),
            1
        );
        assert_eq!(config.local_parts.iter().filter(|p| p == &"cto").count(), 1);
        assert_eq!(config.mx_host.as_deref(), Some("mx.example.com"));
        assert_eq!(config.catch_all_probes, 3);
        assert_eq!(config.mail_from, "probe@example.com");

        let _ = std::fs::remove_file(&domains_file);
        let _ = std::fs::remove_file(&wordlist);
    }

    #[test]
    fn resolve_rejects_invalid_mail_from() {
        assert!(
            parse(&["-d", "example.com", "-f", "not-an-email"])
                .resolve()
                .is_err()
        );
    }

    #[test]
    fn resolve_generates_auto_mail_from() {
        let config = parse(&["-d", "example.com", "--auto-mail-from"])
            .resolve()
            .unwrap();
        assert!(config.mail_from.contains('@'));
        let config = parse(&["-d", "example.com", "--auto-mail-from=corp.example"])
            .resolve()
            .unwrap();
        assert!(config.mail_from.ends_with("@corp.example"));
    }

    #[test]
    fn mx_failover_is_on_by_default() {
        assert!(parse(&["-d", "example.com"]).effective_mx_failover());
        assert!(!parse(&["-d", "example.com", "--no-mx-failover"]).effective_mx_failover());
    }

    #[test]
    fn subcommands_and_global_flags_parse() {
        assert!(matches!(
            parse(&["mx", "example.com"]).command,
            Some(Command::Mx { .. })
        ));
        assert!(matches!(
            parse(&["check-update"]).command,
            Some(Command::CheckUpdate)
        ));
        assert!(
            parse(&["mx", "example.com", "--format", "json"])
                .validate()
                .is_ok()
        );
        assert!(parse(&["-d", "example.com", "--check-update"]).check_update);
        assert_eq!(
            parse(&["-d", "example.com", "--starttls", "required"]).starttls,
            StarttlsMode::Required
        );
    }
}

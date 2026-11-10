//! Output layer: `table` (human), `json` (document), `jsonl`/`csv`
//! (streaming), the `--only-accepted` filter, and the `mx` subcommand report.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use owo_colors::OwoColorize;
use serde::Serialize;

use crate::dns::{DomainSecurity, MxEntry};
use crate::scanner::{DomainReport, ProbeResult, ProbeStatus};

/// Output format selector (clap `ValueEnum` + internal dispatch).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum Format {
    /// Human-readable terminal tables with a per-domain summary.
    Table,
    /// One JSON document with a summary and all domain reports.
    Json,
    /// One JSON object per finalized probe, streamed live.
    Jsonl,
    /// One CSV row per finalized probe, streamed live.
    Csv,
}

/// Aggregated run statistics.
#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    /// Number of domains processed.
    pub domains: usize,
    /// Number of candidate probes finalized.
    pub probes: usize,
    /// `accepted` count.
    pub accepted: usize,
    /// `accepted_catch_all` count.
    pub accepted_catch_all: usize,
    /// `rejected` count.
    pub rejected: usize,
    /// `temporary` count.
    pub temporary: usize,
    /// `policy_blocked` count.
    pub policy_blocked: usize,
    /// `indeterminate` count.
    pub indeterminate: usize,
    /// `error` count.
    pub errors: usize,
    /// Domains confirmed to be catch-all.
    pub catch_all_domains: usize,
    /// Wall-clock seconds.
    pub elapsed_secs: f64,
}

impl RunSummary {
    /// Compute statistics over a set of reports.
    pub fn from_reports(reports: &[DomainReport], elapsed: Duration) -> Self {
        let mut summary = Self {
            domains: reports.len(),
            probes: 0,
            accepted: 0,
            accepted_catch_all: 0,
            rejected: 0,
            temporary: 0,
            policy_blocked: 0,
            indeterminate: 0,
            errors: 0,
            catch_all_domains: 0,
            elapsed_secs: elapsed.as_secs_f64(),
        };
        for report in reports {
            if report.catch_all == Some(true) {
                summary.catch_all_domains += 1;
            }
            for probe in &report.results {
                summary.probes += 1;
                match probe.status {
                    ProbeStatus::Accepted => summary.accepted += 1,
                    ProbeStatus::AcceptedCatchAll => summary.accepted_catch_all += 1,
                    ProbeStatus::Rejected => summary.rejected += 1,
                    ProbeStatus::Temporary => summary.temporary += 1,
                    ProbeStatus::PolicyBlocked => summary.policy_blocked += 1,
                    ProbeStatus::Indeterminate => summary.indeterminate += 1,
                    ProbeStatus::Error => summary.errors += 1,
                }
            }
        }
        summary
    }
}

enum Inner {
    Text(Box<dyn Write + Send>),
    Csv(Box<csv::Writer<Box<dyn Write + Send>>>),
}

/// Destination for probe output: stdout (default) or `--output` file, in the
/// requested format, optionally filtering to accepted results only.
pub struct OutputSink {
    format: Format,
    only_accepted: bool,
    color: bool,
    term_width: u16,
    show_banner: bool,
    inner: Inner,
}

impl OutputSink {
    /// Open the sink. `show_banner` controls the cosmetic table header (only
    /// meaningful on an interactive terminal).
    ///
    /// # Errors
    ///
    /// Returns an error when the output file cannot be created.
    pub fn create(
        format: Format,
        only_accepted: bool,
        show_banner: bool,
        path: Option<&Path>,
    ) -> Result<Self> {
        let (writer, color, term_width): (Box<dyn Write + Send>, bool, u16) = match path {
            Some(p) => {
                let file = File::create(p)
                    .with_context(|| format!("cannot create output file {}", p.display()))?;
                (Box::new(BufWriter::new(file)), false, 110)
            }
            None => {
                let term = console::Term::stdout();
                let attended = term.features().is_attended();
                (
                    Box::new(io::stdout()),
                    console::colors_enabled() && attended,
                    term.size().1.max(60),
                )
            }
        };
        let inner = if format == Format::Csv {
            Inner::Csv(Box::new(csv::Writer::from_writer(writer)))
        } else {
            Inner::Text(writer)
        };
        Ok(Self {
            format,
            only_accepted,
            color,
            term_width,
            show_banner,
            inner,
        })
    }

    fn passes(&self, result: &ProbeResult) -> bool {
        !self.only_accepted
            || matches!(
                result.status,
                ProbeStatus::Accepted | ProbeStatus::AcceptedCatchAll
            )
    }

    /// Stream one finalized probe result (jsonl/csv formats; no-op otherwise).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying writer fails.
    pub fn emit(&mut self, result: &ProbeResult) -> Result<()> {
        if !self.passes(result) {
            return Ok(());
        }
        match &mut self.inner {
            Inner::Text(writer) if self.format == Format::Jsonl => {
                writeln!(writer, "{}", serde_json::to_string(result)?)
                    .context("writing jsonl result to output")?;
                writer.flush().context("flushing jsonl output")?;
                Ok(())
            }
            Inner::Csv(writer) => {
                writer.serialize(result).context("serializing csv row")?;
                writer.flush().context("flushing csv output")?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Write the final report document (table/json formats). jsonl and csv
    /// were already streamed via [`OutputSink::emit`].
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying writer fails.
    pub fn write_reports(&mut self, reports: &[DomainReport], elapsed: Duration) -> Result<()> {
        if self.format == Format::Jsonl || self.format == Format::Csv {
            return Ok(());
        }
        let reports = self.filtered(reports);
        let color = self.color;
        let width = self.term_width;
        let show_banner = self.show_banner;
        match &mut self.inner {
            Inner::Text(writer) => match self.format {
                Format::Table => {
                    let writer = writer.as_mut();
                    if show_banner {
                        writeln!(
                            writer,
                            "rcptx {} — {} domain(s), table report",
                            env!("CARGO_PKG_VERSION"),
                            reports.len()
                        )?;
                        writeln!(writer)?;
                    }
                    for report in &reports {
                        write_domain_block(writer, report, color, width)?;
                    }
                    let summary = RunSummary::from_reports(&reports, elapsed);
                    write_summary_line(writer, &summary, color)?;
                    if summary.accepted_catch_all > 0 {
                        writeln!(
                            writer,
                            "  * accepted on a domain that accepts every address (catch-all)"
                        )?;
                    }
                    Ok(())
                }
                Format::Json => {
                    #[derive(Serialize)]
                    struct JsonDoc<'a> {
                        summary: RunSummary,
                        domains: &'a [DomainReport],
                    }
                    let doc = JsonDoc {
                        summary: RunSummary::from_reports(&reports, elapsed),
                        domains: &reports,
                    };
                    writeln!(writer, "{}", serde_json::to_string_pretty(&doc)?)
                        .context("writing json document")?;
                    Ok(())
                }
                Format::Jsonl | Format::Csv => unreachable!("guarded above"),
            },
            Inner::Csv(_) => Err(anyhow!("internal error: csv sink used as a text writer")),
        }
    }

    /// Flush any buffered bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when flushing fails.
    pub fn finish(&mut self) -> Result<()> {
        match &mut self.inner {
            Inner::Text(writer) => writer.flush().context("flushing output"),
            Inner::Csv(writer) => writer.flush().context("flushing csv output"),
        }
    }

    fn filtered(&self, reports: &[DomainReport]) -> Vec<DomainReport> {
        if !self.only_accepted {
            return reports.to_vec();
        }
        reports
            .iter()
            .map(|report| {
                let mut clone = report.clone();
                clone.results.retain(|probe| self.passes(probe));
                clone
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

fn write_domain_block(
    writer: &mut dyn Write,
    report: &DomainReport,
    color: bool,
    width: u16,
) -> Result<()> {
    writeln!(
        writer,
        "{}",
        paint_if(color, &format!(" {} ", report.domain), |t| t
            .bold()
            .to_string())
    )?;
    writeln!(writer, "{}", "─".repeat(usize::from(width.min(100))))?;

    let mx = if report.mx_records.is_empty() {
        "(none)".to_string()
    } else {
        report
            .mx_records
            .iter()
            .map(|entry| {
                if entry.exchange == "." {
                    format!("{} (null MX)", entry.preference)
                } else {
                    format!("{} {}", entry.preference, entry.exchange)
                }
            })
            .collect::<Vec<_>>()
            .join("  |  ")
    };
    write_kv(writer, "MX", &mx, color)?;
    write_kv(
        writer,
        "Provider",
        report.provider.as_deref().unwrap_or("(unrecognized)"),
        color,
    )?;
    write_kv(
        writer,
        "SPF",
        report.spf.as_deref().unwrap_or("(not published)"),
        color,
    )?;
    write_kv(
        writer,
        "DMARC",
        report.dmarc.as_deref().unwrap_or("(not published)"),
        color,
    )?;
    let catch_all = match report.catch_all {
        Some(true) => "YES — every address is accepted",
        Some(false) => "no",
        None => "unknown (probes were inconclusive)",
    };
    write_kv(writer, "Catch-All", catch_all, color)?;
    for note in &report.notes {
        write_kv(writer, "Note", note, color)?;
    }
    writeln!(writer)?;

    if report.results.is_empty() {
        writeln!(writer, "  (no candidate results for this domain)")?;
        writeln!(writer)?;
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_width(width.max(60));
    table.set_header(vec![
        "Email", "Status", "Code", "ESC", "Try", "ms", "Message",
    ]);
    for probe in &report.results {
        table.add_row(vec![
            Cell::new(&probe.email),
            status_cell(probe.status, color),
            Cell::new(probe.smtp_code.map(|c| c.to_string()).unwrap_or_default()),
            Cell::new(probe.enhanced_code.clone().unwrap_or_default()),
            Cell::new(probe.attempts.to_string()),
            Cell::new(
                probe
                    .latency_ms
                    .map(|ms| ms.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::new(one_line(&probe.message, 60)),
        ]);
    }
    writeln!(writer, "{table}")?;
    writeln!(writer)?;
    Ok(())
}

fn write_summary_line(writer: &mut dyn Write, summary: &RunSummary, color: bool) -> Result<()> {
    let parts = [
        paint_if(color, &format!("{} accepted", summary.accepted), |t| {
            t.green().to_string()
        }),
        paint_if(
            color,
            &format!("{} catch-all*", summary.accepted_catch_all),
            |t| t.cyan().to_string(),
        ),
        paint_if(color, &format!("{} rejected", summary.rejected), |t| {
            t.red().to_string()
        }),
        paint_if(color, &format!("{} temporary", summary.temporary), |t| {
            t.yellow().to_string()
        }),
        paint_if(
            color,
            &format!("{} policy-blocked", summary.policy_blocked),
            |t| t.magenta().to_string(),
        ),
        paint_if(
            color,
            &format!("{} indeterminate", summary.indeterminate),
            |t| t.blue().to_string(),
        ),
        paint_if(color, &format!("{} error", summary.errors), |t| {
            t.bright_red().to_string()
        }),
    ];
    writeln!(
        writer,
        "{}: {} probe(s) across {} domain(s) — {} — {:.1}s",
        paint_if(color, "Summary", |t| t.bold().to_string()),
        summary.probes,
        summary.domains,
        parts.join(" · "),
        summary.elapsed_secs
    )?;
    Ok(())
}

fn status_cell(status: ProbeStatus, color: bool) -> Cell {
    let label = status_label(status);
    if !color {
        return Cell::new(label);
    }
    let table_color = match status {
        ProbeStatus::Accepted => Color::Green,
        ProbeStatus::AcceptedCatchAll => Color::Cyan,
        ProbeStatus::Rejected => Color::Red,
        ProbeStatus::Temporary => Color::Yellow,
        ProbeStatus::PolicyBlocked => Color::Magenta,
        ProbeStatus::Indeterminate => Color::Blue,
        ProbeStatus::Error => Color::DarkGrey,
    };
    Cell::new(label).fg(table_color)
}

fn status_label(status: ProbeStatus) -> &'static str {
    match status {
        ProbeStatus::Accepted => "accepted",
        ProbeStatus::AcceptedCatchAll => "accepted*",
        ProbeStatus::Rejected => "rejected",
        ProbeStatus::Temporary => "temporary",
        ProbeStatus::PolicyBlocked => "policy-blocked",
        ProbeStatus::Indeterminate => "indeterminate",
        ProbeStatus::Error => "error",
    }
}

fn write_kv(writer: &mut dyn Write, key: &str, value: &str, color: bool) -> Result<()> {
    let padded = format!("{key:<9}");
    writeln!(
        writer,
        "  {} {}",
        paint_if(color, &padded, |t| t.bright_blue().to_string()),
        one_line(value, 160)
    )?;
    Ok(())
}

fn paint_if(on: bool, text: &str, painter: impl Fn(&str) -> String) -> String {
    if on { painter(text) } else { text.to_string() }
}

fn one_line(text: &str, max_chars: usize) -> String {
    let flat: String = text
        .chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else {
                c
            }
        })
        .collect();
    let collapsed = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > max_chars {
        let truncated: String = collapsed.chars().take(max_chars).collect();
        format!("{truncated}…")
    } else {
        collapsed
    }
}

// ---------------------------------------------------------------------------
// `mx` subcommand report
// ---------------------------------------------------------------------------

/// Inputs for [`write_mx_report`].
pub struct MxReport<'a> {
    /// Domain that was inspected.
    pub domain: &'a str,
    /// Resolved MX records (sorted by preference).
    pub mx: &'a [MxEntry],
    /// SPF/DMARC posture.
    pub security: &'a DomainSecurity,
    /// Inferred provider, when recognized.
    pub provider: Option<&'a str>,
    /// Output format.
    pub format: Format,
    /// ANSI color for terminal table output.
    pub color: bool,
    /// Terminal width for table layout.
    pub width: u16,
}

/// Write the DNS-only reconnaissance report for the `mx` subcommand.
///
/// # Errors
///
/// Returns an error when the underlying writer fails.
pub fn write_mx_report(writer: &mut dyn Write, report: &MxReport<'_>) -> Result<()> {
    let MxReport {
        domain,
        mx,
        security,
        provider,
        format,
        color,
        width,
    } = *report;
    match format {
        Format::Json => {
            #[derive(Serialize)]
            struct MxDoc<'a> {
                domain: &'a str,
                provider: Option<&'a str>,
                spf: Option<&'a str>,
                dmarc: Option<&'a str>,
                mx: &'a [MxEntry],
            }
            let doc = MxDoc {
                domain,
                provider,
                spf: security.spf.as_deref(),
                dmarc: security.dmarc.as_deref(),
                mx,
            };
            writeln!(writer, "{}", serde_json::to_string_pretty(&doc)?)?;
        }
        Format::Jsonl => {
            for entry in mx {
                writeln!(
                    writer,
                    "{}",
                    serde_json::json!({"domain": domain, "preference": entry.preference, "exchange": entry.exchange})
                )?;
            }
        }
        Format::Csv => {
            #[derive(Serialize)]
            struct MxRow<'a> {
                domain: &'a str,
                preference: u16,
                exchange: &'a str,
            }
            let mut csv_writer = csv::Writer::from_writer(writer);
            for entry in mx {
                csv_writer.serialize(MxRow {
                    domain,
                    preference: entry.preference,
                    exchange: &entry.exchange,
                })?;
            }
            csv_writer.flush()?;
        }
        Format::Table => {
            writeln!(
                writer,
                "{}",
                paint_if(color, &format!(" MX recon: {domain} "), |t| t
                    .bold()
                    .to_string())
            )?;
            writeln!(writer, "{}", "─".repeat(usize::from(width.min(100))))?;
            write_kv(
                writer,
                "Provider",
                provider.unwrap_or("(unrecognized)"),
                color,
            )?;
            write_kv(
                writer,
                "SPF",
                security.spf.as_deref().unwrap_or("(not published)"),
                color,
            )?;
            write_kv(
                writer,
                "DMARC",
                security.dmarc.as_deref().unwrap_or("(not published)"),
                color,
            )?;
            writeln!(writer)?;
            if mx.is_empty() {
                writeln!(writer, "  (no MX records found)")?;
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_width(width.max(40));
            table.set_header(vec!["Preference", "Exchange"]);
            for entry in mx {
                table.add_row(vec![
                    Cell::new(entry.preference.to_string()),
                    Cell::new(if entry.exchange == "." {
                        "(null MX — does not accept mail)".to_string()
                    } else {
                        entry.exchange.clone()
                    }),
                ]);
            }
            writeln!(writer, "{table}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::MxEntry;

    fn probe(status: ProbeStatus) -> ProbeResult {
        ProbeResult {
            domain: "example.com".to_string(),
            local_part: "info".to_string(),
            email: "info@example.com".to_string(),
            status,
            smtp_code: Some(250),
            enhanced_code: Some("2.1.5".to_string()),
            stage: Some("rcpt-to".to_string()),
            message: "2.1.5 Ok".to_string(),
            mx_host: "mx.example.com".to_string(),
            attempts: 1,
            latency_ms: Some(42),
        }
    }

    fn report(results: Vec<ProbeResult>) -> DomainReport {
        DomainReport {
            domain: "example.com".to_string(),
            mx_records: vec![MxEntry {
                preference: 10,
                exchange: "mx.example.com".to_string(),
            }],
            provider: Some("Google Workspace".to_string()),
            spf: Some("v=spf1 -all".to_string()),
            dmarc: None,
            catch_all: Some(false),
            probed_via: Some("mx.example.com".to_string()),
            interrupted: false,
            notes: Vec::new(),
            results,
        }
    }

    fn temp_path(extension: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "rcptx-test-out-{}.{}",
            uuid::Uuid::new_v4().simple(),
            extension
        ))
    }

    #[test]
    fn one_line_flattens_and_truncates() {
        assert_eq!(one_line("  a\tb\n c  ", 10), "a b c");
        assert_eq!(one_line(&"x".repeat(20), 5), "xxxxx…");
        assert_eq!(one_line("", 5), "");
        assert_eq!(one_line("ok", 5), "ok");
    }

    #[test]
    fn summary_counts_statuses() {
        let reports = vec![
            report(vec![
                probe(ProbeStatus::Accepted),
                probe(ProbeStatus::Accepted),
                probe(ProbeStatus::Rejected),
            ]),
            report(vec![
                probe(ProbeStatus::Temporary),
                probe(ProbeStatus::Error),
            ]),
        ];
        let summary = RunSummary::from_reports(&reports, Duration::from_secs(2));
        assert_eq!(summary.domains, 2);
        assert_eq!(summary.probes, 5);
        assert_eq!(summary.accepted, 2);
        assert_eq!(summary.rejected, 1);
        assert_eq!(summary.temporary, 1);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.catch_all_domains, 0);
        assert!((summary.elapsed_secs - 2.0).abs() < 0.01);
    }

    #[test]
    fn jsonl_sink_streams_and_filters() {
        let path = temp_path("jsonl");
        let mut sink = OutputSink::create(Format::Jsonl, true, false, Some(&path)).unwrap();
        sink.emit(&probe(ProbeStatus::Accepted)).unwrap();
        sink.emit(&probe(ProbeStatus::Rejected)).unwrap(); // filtered out
        sink.emit(&probe(ProbeStatus::AcceptedCatchAll)).unwrap();
        sink.finish().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["status"], "accepted");
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["status"], "accepted_catch_all");
    }

    #[test]
    fn csv_sink_writes_header_and_rows() {
        #[derive(serde::Deserialize)]
        struct Row {
            email: String,
            status: String,
        }
        let path = temp_path("csv");
        let mut sink = OutputSink::create(Format::Csv, false, false, Some(&path)).unwrap();
        sink.emit(&probe(ProbeStatus::Accepted)).unwrap();
        sink.finish().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let mut records = csv::Reader::from_reader(content.as_bytes());
        assert_eq!(records.headers().unwrap().len(), 11);
        let rows: Vec<Row> = records.deserialize().collect::<Result<_, _>>().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "accepted");
        assert_eq!(rows[0].email, "info@example.com");
    }

    #[test]
    fn json_sink_writes_a_parseable_document() {
        let path = temp_path("json");
        let mut sink = OutputSink::create(Format::Json, false, false, Some(&path)).unwrap();
        let reports = vec![report(vec![probe(ProbeStatus::Accepted)])];
        sink.write_reports(&reports, Duration::from_secs(1))
            .unwrap();
        sink.finish().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(doc["summary"]["domains"], 1);
        assert_eq!(doc["domains"][0]["domain"], "example.com");
        assert_eq!(doc["domains"][0]["catch_all"], false);
        assert_eq!(doc["domains"][0]["results"][0]["status"], "accepted");
    }

    #[test]
    fn table_sink_writes_domain_blocks() {
        let path = temp_path("txt");
        let mut sink = OutputSink::create(Format::Table, false, false, Some(&path)).unwrap();
        let reports = vec![report(vec![
            probe(ProbeStatus::Accepted),
            probe(ProbeStatus::Rejected),
        ])];
        sink.write_reports(&reports, Duration::from_secs(1))
            .unwrap();
        sink.finish().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(content.contains("example.com"));
        assert!(content.contains("Google Workspace"));
        assert!(content.contains("accepted"));
        assert!(content.contains("rejected"));
        assert!(content.contains("Summary"));
    }

    #[test]
    fn only_accepted_filter_drops_non_hits_from_reports() {
        let path = temp_path("json");
        let mut sink = OutputSink::create(Format::Json, true, false, Some(&path)).unwrap();
        let reports = vec![report(vec![
            probe(ProbeStatus::Rejected),
            probe(ProbeStatus::Accepted),
        ])];
        sink.write_reports(&reports, Duration::from_secs(1))
            .unwrap();
        sink.finish().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        let results = doc["domains"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["status"], "accepted");
    }
}

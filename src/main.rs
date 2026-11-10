//! `rcptx` binary — argument parsing, progress/logging setup, signal
//! handling and exit-code policy. All real work lives in the `rcptx`
//! library crate so it stays integration-testable.

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::MultiProgress;
use rcptx::cli::{Cli, Command};
use rcptx::dns;
use rcptx::output::{self, OutputSink, RunSummary, write_mx_report};
use rcptx::scanner;
use rcptx::update::{self, UpdateInfo};
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            // clap exits with code 2 by default; we reserve 2 for the
            // "port blocked" heuristic, so surface usage errors as 1.
            let message = format!("{err}");
            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                println!("{message}");
                return ExitCode::SUCCESS;
            }
            eprintln!("{message}");
            eprintln!("pass --help for usage");
            return ExitCode::from(1);
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("error: failed to start the async runtime: {e}");
            return ExitCode::from(1);
        }
    };

    match runtime.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    cli.validate().context("invalid configuration")?;

    if cli.check_update {
        // Never fatal for the main run — a flaky network must not stop a scan.
        let quiet = cli.effective_quiet();
        match update::check_for_update(Duration::from_secs(8)).await {
            Ok(info) if info.update_available => eprintln!("{}", format_update_notice(&info)),
            Ok(info) if !quiet => eprintln!(
                "rcptx {} is up to date (latest release: {})",
                update::CURRENT_VERSION,
                info.latest
            ),
            Ok(_) => {}
            Err(e) => eprintln!("warning: update check failed: {e:#}"),
        }
    }

    match &cli.command {
        Some(Command::Mx { domain }) => run_mx_subcommand(&cli, domain).await,
        Some(Command::CheckUpdate) => run_check_update_subcommand().await,
        Some(Command::Providers) => run_providers_subcommand(&cli),
        None => run_probe(&cli).await,
    }
}

async fn run_check_update_subcommand() -> Result<ExitCode> {
    match update::check_for_update(Duration::from_secs(15)).await {
        Ok(info) => {
            println!("current version : {}", info.current);
            println!(
                "latest release  : {}{}",
                info.latest,
                if info.prerelease { " (prerelease)" } else { "" }
            );
            if info.update_available {
                println!("update available: {}", info.release_url);
                println!("download        : {}", update::RELEASES_URL);
            } else {
                println!("you are up to date");
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("error: update check failed: {e:#}");
            eprintln!("check {} manually", update::RELEASES_URL);
            Ok(ExitCode::from(1))
        }
    }
}

fn format_update_notice(info: &UpdateInfo) -> String {
    format!(
        "update available: {} → {} — {}",
        info.current, info.latest, info.release_url
    )
}

async fn run_probe(cli: &Cli) -> Result<ExitCode> {
    let config = cli.resolve()?;
    let quiet = cli.effective_quiet();
    init_tracing(cli.verbose, quiet);

    let progress = if quiet {
        None
    } else {
        Some(MultiProgress::new())
    };

    // Graceful shutdown: first Ctrl+C sets the flag and lets in-flight probes
    // drain; a second Ctrl+C aborts immediately.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let flag = shutdown.clone();
        tokio::spawn(async move {
            loop {
                if tokio::signal::ctrl_c().await.is_ok() && flag.swap(true, Ordering::Relaxed) {
                    std::process::exit(130);
                }
                eprintln!(
                    "\ninterrupt received — draining in-flight probes (partial results will be printed); press Ctrl+C again to abort"
                );
            }
        });
    }

    let mut sink = OutputSink::create(
        config.format,
        config.only_accepted,
        !quiet && cli.output.is_none(),
        cli.output.as_deref(),
    )?;
    let started = Instant::now();

    let outcome = scanner::run(&config, progress, shutdown, &mut |result| {
        if let Err(e) = sink.emit(result) {
            eprintln!("error: streaming a result failed: {e:#}");
        }
    })
    .await?;

    sink.write_reports(&outcome.reports, started.elapsed())?;
    sink.finish()?;

    if !quiet {
        let summary = RunSummary::from_reports(&outcome.reports, started.elapsed());
        eprintln!(
            "rcptx finished: {} domain(s), {} probe(s) in {:.1}s",
            summary.domains, summary.probes, summary.elapsed_secs
        );
    }
    if outcome.interrupted {
        eprintln!("note: run interrupted — partial results are shown");
    }

    if outcome.tcp_attempts > 0 && outcome.tcp_connect_timeouts == outcome.tcp_attempts {
        eprintln!(
            "warning: all {} TCP connection attempts timed out — outbound port {} appears blocked",
            outcome.tcp_attempts, config.port
        );
        return Ok(ExitCode::from(2));
    }
    Ok(ExitCode::SUCCESS)
}

async fn run_mx_subcommand(cli: &Cli, domain: &str) -> Result<ExitCode> {
    let quiet = cli.effective_quiet();
    init_tracing(cli.verbose, quiet);

    let domain = domain
        .trim()
        .trim_start_matches("mailto:")
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or(domain)
        .trim_end_matches('.')
        .to_lowercase();
    if domain.is_empty() || domain.chars().any(char::is_whitespace) {
        anyhow::bail!("invalid domain {domain:?} for the mx subcommand");
    }

    let resolver = dns::DnsResolver::new(cli.dns_server)?;
    let (mx_lookup, security) = futures::join!(resolver.mx(&domain), resolver.security(&domain));
    let mx = mx_lookup?;
    let provider_match = dns::detect_provider_detail(&mx, security.spf.as_deref());
    let provider = provider_match.as_ref().map(|matched| matched.name);
    let match_description = provider_match.as_ref().map(|matched| matched.describe());

    let (mut writer, color, width) = report_writer(cli)?;
    let report = output::MxReport {
        domain: &domain,
        mx: &mx,
        security: &security,
        provider,
        provider_match: match_description.as_deref(),
        verbose: cli.verbose > 0,
        format: cli.format,
        color,
        width,
    };
    write_mx_report(writer.as_mut(), &report)?;
    writer.flush().ok();
    Ok(ExitCode::SUCCESS)
}

fn run_providers_subcommand(cli: &Cli) -> Result<ExitCode> {
    let quiet = cli.effective_quiet();
    init_tracing(cli.verbose, quiet);
    let (mut writer, color, width) = report_writer(cli)?;
    output::write_provider_list(
        writer.as_mut(),
        dns::PROVIDER_FINGERPRINTS,
        cli.format,
        color,
        width,
    )?;
    writer.flush().ok();
    Ok(ExitCode::SUCCESS)
}

/// Open the report destination for the DNS-facing subcommands: `--output`
/// file or stdout, plus color and width hints for table rendering.
fn report_writer(cli: &Cli) -> Result<(Box<dyn std::io::Write>, bool, u16)> {
    let writer: Box<dyn std::io::Write> = match &cli.output {
        Some(path) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(path)
                .with_context(|| format!("cannot create output file {}", path.display()))?,
        )),
        None => Box::new(std::io::stdout()),
    };
    let color = cli.output.is_none() && console::colors_enabled();
    let width = console::Term::stdout().size().1.max(60);
    Ok((writer, color, width))
}

fn init_tracing(verbose: u8, quiet: bool) {
    let default_filter = if quiet {
        "error".to_string()
    } else {
        match verbose {
            0 => "warn".to_string(),
            // -v keeps logs at warn but reveals the raw SMTP transcript.
            1 => "warn,rcptx::transcript=debug".to_string(),
            2 => "debug".to_string(),
            _ => "trace".to_string(),
        }
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

//! `smtp-probe` — smart asynchronous SMTP reconnaissance & deliverability CLI.
//!
//! Pipeline: parse CLI → validate → resolve inputs → (per domain) MX + SPF/
//! DMARC recon → catch-all probing → candidate probing with session reuse →
//! greylist retries → formatted output. Exit codes: 0 success, 1
//! configuration/runtime error, 2 outbound port appears blocked.

#![forbid(unsafe_code)]

mod cli;
mod dns;
mod output;
mod presets;
mod scanner;
mod smtp;

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::MultiProgress;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command};
use crate::output::{write_mx_report, OutputSink, RunSummary};

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

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
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

    if let Some(Command::Mx { domain }) = &cli.command {
        return run_mx_subcommand(&cli, domain).await;
    }

    let config = cli.resolve()?;
    let quiet = cli.effective_quiet();
    init_tracing(cli.verbose, quiet);

    let progress = if quiet { None } else { Some(MultiProgress::new()) };

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
            "smtp-probe finished: {} domain(s), {} probe(s) in {:.1}s",
            summary.domains,
            summary.probes,
            summary.elapsed_secs
        );
    }
    if outcome.interrupted {
        eprintln!("note: run interrupted — partial results are shown");
    }

    if outcome.tcp_attempts > 0 && outcome.tcp_connect_timeouts == outcome.tcp_attempts {
        eprintln!(
            "warning: all {} TCP connection attempts timed out — outbound port {} appears blocked",
            outcome.tcp_attempts,
            config.port
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
    let provider = dns::detect_provider(&mx, security.spf.as_deref());

    let mut writer: Box<dyn std::io::Write> = match &cli.output {
        Some(path) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(path).with_context(|| format!("cannot create output file {}", path.display()))?,
        )),
        None => Box::new(std::io::stdout()),
    };
    let color = cli.output.is_none() && console::colors_enabled();
    let width = console::Term::stdout().size().1.max(60);
    let report = output::MxReport {
        domain: &domain,
        mx: &mx,
        security: &security,
        provider,
        format: cli.format,
        color,
        width,
    };
    write_mx_report(writer.as_mut(), &report)?;
    writer.flush().ok();
    Ok(ExitCode::SUCCESS)
}

fn init_tracing(verbose: u8, quiet: bool) {
    let default_filter = if quiet {
        "error".to_string()
    } else {
        match verbose {
            0 => "warn".to_string(),
            // -v keeps logs at warn but reveals the raw SMTP transcript.
            1 => "warn,smtp_probe::transcript=debug".to_string(),
            2 => "debug".to_string(),
            _ => "trace".to_string(),
        }
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

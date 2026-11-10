//! Scan orchestration: MX failover, session reuse with `RSET` multiplexing,
//! transparent reconnect-and-resume, catch-all probing, jittered rate
//! limiting, greylist retries, and graceful Ctrl+C shutdown.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rand::Rng;
use serde::Serialize;
use uuid::Uuid;

use crate::cli::ResolvedConfig;
use crate::dns::{detect_provider, DnsResolver, MxEntry};
use crate::smtp::client::{next_conn_id, ConnectConfig};
use crate::smtp::{SmtpConnection, SmtpError, Stage, SmtpReply};

/// Final verdict for one probed candidate.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    /// `250`/`251` — mailbox exists and accepts mail.
    Accepted,
    /// `250`/`251` on a domain whose random catch-all probes were also accepted.
    AcceptedCatchAll,
    /// `550 5.1.1` (or equivalent) — user unknown / mailbox unavailable.
    Rejected,
    /// `4xx` — greylisted, rate limited or otherwise temporary.
    Temporary,
    /// `550 5.7.x`, `554`, sender-stage rejection — anti-enumeration / blocklist policy.
    PolicyBlocked,
    /// `252` — cannot VRFY, but would accept the message.
    Indeterminate,
    /// Connection timeout, TLS failure, unexpected EOF, unreachable MX.
    Error,
}

/// Result of one candidate probe.
#[derive(Clone, Debug, Serialize)]
pub struct ProbeResult {
    /// Target domain.
    pub domain: String,
    /// Local part that was probed.
    pub local_part: String,
    /// Full address probed.
    pub email: String,
    /// Final verdict.
    pub status: ProbeStatus,
    /// 3-digit SMTP reply code, when a reply was received.
    pub smtp_code: Option<u16>,
    /// RFC 3463 enhanced status code, when present.
    pub enhanced_code: Option<String>,
    /// Stage the (final) reply or failure belongs to.
    pub stage: Option<String>,
    /// Short human-readable reply/error summary.
    pub message: String,
    /// Mail exchanger the probe actually ran against.
    pub mx_host: String,
    /// Number of attempts (1 + greylist retries).
    pub attempts: u16,
    /// Round-trip latency of the MAIL FROM + RCPT TO exchange.
    pub latency_ms: Option<u64>,
}

/// Aggregate report for one target domain.
#[derive(Debug, Clone, Serialize)]
pub struct DomainReport {
    /// The target domain.
    pub domain: String,
    /// MX records discovered (sorted by preference; `.` = null MX).
    pub mx_records: Vec<MxEntry>,
    /// Inferred receiving platform (Google Workspace, Microsoft 365, …).
    pub provider: Option<String>,
    /// `v=spf1` record, when found.
    pub spf: Option<String>,
    /// `v=DMARC1` record, when found.
    pub dmarc: Option<String>,
    /// `Some(true)`/`Some(false)` once determined; `None` when inconclusive.
    pub catch_all: Option<bool>,
    /// Host the probes actually ran against.
    pub probed_via: Option<String>,
    /// True when interrupted by Ctrl+C mid-domain.
    pub interrupted: bool,
    /// Human-readable annotations (failovers, fallbacks, skips).
    pub notes: Vec<String>,
    /// Per-candidate results, in candidate order.
    pub results: Vec<ProbeResult>,
}

/// Everything `main` needs after a run.
#[derive(Debug, Default)]
pub struct ScanOutcome {
    /// One report per processed domain.
    pub reports: Vec<DomainReport>,
    /// Total TCP connect attempts made.
    pub tcp_attempts: u64,
    /// TCP connect attempts that ended in a timeout (egress-block heuristic).
    pub tcp_connect_timeouts: u64,
    /// True when the run was cut short by Ctrl+C.
    pub interrupted: bool,
}

/// A shared, lockable result callback so concurrent workers can stream
/// finalized results to the output sink.
type EmitFn<'a> = &'a mut dyn FnMut(&ProbeResult);

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the whole scan for every configured target domain.
///
/// # Errors
///
/// Returns an error only for fatal setup problems (e.g. DNS resolver
/// creation); per-domain failures land in the [`DomainReport`] notes instead.
pub async fn run(
    config: &ResolvedConfig,
    progress: Option<MultiProgress>,
    shutdown: Arc<AtomicBool>,
    on_result: &mut dyn FnMut(&ProbeResult),
) -> Result<ScanOutcome> {
    let dns = DnsResolver::new(config.dns_server)?;
    let attempts = AtomicU64::new(0);
    let timeouts = AtomicU64::new(0);

    let domains_bar = progress.as_ref().map(|mp| {
        let bar = mp.add(ProgressBar::new(config.targets.len() as u64));
        bar.set_style(
            ProgressStyle::with_template("[{elapsed_precise}] {bar:28.cyan/blue} {pos}/{len} domains · {msg}")
                .expect("valid progress template"),
        );
        bar
    });

    let mut outcome = ScanOutcome::default();
    for domain in &config.targets {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        if let Some(bar) = &domains_bar {
            bar.set_message(format!("current: {domain}"));
        }
        let report = scan_domain(
            domain,
            config,
            &dns,
            progress.as_ref(),
            &shutdown,
            &attempts,
            &timeouts,
            on_result,
        )
        .await?;
        if let Some(bar) = &domains_bar {
            bar.inc(1);
        }
        outcome.reports.push(report);
    }

    if let Some(bar) = &domains_bar {
        bar.finish_with_message("done");
    }
    outcome.interrupted = shutdown.load(Ordering::Relaxed) || outcome.reports.iter().any(|r| r.interrupted);
    outcome.tcp_attempts = attempts.load(Ordering::Relaxed);
    outcome.tcp_connect_timeouts = timeouts.load(Ordering::Relaxed);
    Ok(outcome)
}

fn set_phase(spinner: &Option<ProgressBar>, message: String) {
    if let Some(sp) = spinner {
        sp.set_message(message);
    }
}

#[allow(clippy::too_many_arguments)]
async fn scan_domain(
    domain: &str,
    config: &ResolvedConfig,
    dns: &DnsResolver,
    progress: Option<&MultiProgress>,
    shutdown: &AtomicBool,
    attempts: &AtomicU64,
    timeouts: &AtomicU64,
    on_result: &mut dyn FnMut(&ProbeResult),
) -> Result<DomainReport> {
    let spinner = progress.map(|mp| {
        let sp = mp.add(ProgressBar::new_spinner());
        sp.set_style(ProgressStyle::with_template("{spinner:.green} {msg}").expect("valid spinner template"));
        sp.enable_steady_tick(Duration::from_millis(120));
        sp
    });

    let mut report = DomainReport {
        domain: domain.to_string(),
        mx_records: Vec::new(),
        provider: None,
        spf: None,
        dmarc: None,
        catch_all: None,
        probed_via: None,
        interrupted: false,
        notes: Vec::new(),
        results: Vec::new(),
    };

    // ------------------------------------------------------------------
    // 1. MX resolution + security pre-flight (concurrent)
    // ------------------------------------------------------------------
    set_phase(&spinner, format!("[{domain}] MX + SPF/DMARC lookup"));
    let (mx, security) = match &config.mx_host {
        Some(host) => {
            let sec = dns.security(domain).await;
            (vec![MxEntry { preference: 0, exchange: host.clone() }], sec)
        }
        None => {
            let (lookup, sec) = futures::join!(dns.mx(domain), dns.security(domain));
            let entries = match lookup {
                Ok(entries) => entries,
                Err(e) => {
                    report
                        .notes
                        .push(format!("MX lookup failed: {e:#} — falling back to implicit MX (domain A record)"));
                    vec![MxEntry { preference: 0, exchange: domain.to_string() }]
                }
            };
            (entries, sec)
        }
    };
    report.mx_records = mx.clone();
    report.provider = detect_provider(&mx, security.spf.as_deref()).map(str::to_string);
    report.spf = security.spf;
    report.dmarc = security.dmarc;
    if let Some(provider) = &report.provider {
        report.notes.push(format!("receiving infrastructure looks like {provider} (inferred from MX/SPF)"));
    }

    let mut usable: Vec<String> = mx
        .iter()
        .filter(|entry| !entry.exchange.is_empty() && entry.exchange != ".")
        .map(|entry| entry.exchange.clone())
        .collect();
    usable.dedup();
    if usable.is_empty() {
        report.notes.push("domain does not accept mail (null MX or no MX records found)".to_string());
        set_phase(&spinner, format!("[{domain}] skipped: no usable MX"));
        if let Some(sp) = spinner {
            sp.finish_with_message(format!("[{domain}] skipped: no usable MX"));
        }
        return Ok(report);
    }
    if !config.mx_failover {
        usable.truncate(1);
    }
    report.probed_via = Some(usable[0].clone());

    // ------------------------------------------------------------------
    // 2. Catch-all probing with random UUID addresses
    // ------------------------------------------------------------------
    let mut catch_all: Option<bool> = None;
    if config.catch_all_probes > 0 {
        let mut prober = Prober::new(&usable, config, attempts, timeouts);
        let mut rng = rand::thread_rng();
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        let mut inconclusive = 0usize;
        for i in 0..config.catch_all_probes {
            if shutdown.load(Ordering::Relaxed) {
                report.interrupted = true;
                break;
            }
            set_phase(
                &spinner,
                format!("[{domain}] catch-all probe {}/{}", i + 1, config.catch_all_probes),
            );
            let email = format!("{}.probe@{domain}", Uuid::new_v4().simple());
            let outcome = prober.probe(&email, &mut rng, shutdown).await;
            match outcome.reply.map(|(_, reply)| reply.code) {
                Some(code) if code == 250 || code == 251 => accepted += 1,
                Some(code) if code >= 500 => rejected += 1,
                Some(_) | None => inconclusive += 1,
            }
        }
        prober.finish().await;
        let probes = accepted + rejected + inconclusive;
        if probes > 0 {
            if accepted == probes {
                catch_all = Some(true);
                report
                    .notes
                    .push(format!("catch-all confirmed: {accepted}/{probes} random addresses accepted"));
            } else if accepted > 0 {
                catch_all = Some(false);
                report.notes.push(format!(
                    "inconsistent catch-all responses: {accepted} accepted, {rejected} rejected, {inconclusive} inconclusive"
                ));
            } else if inconclusive == 0 {
                catch_all = Some(false);
            }
        }
    }
    report.catch_all = catch_all;

    if catch_all == Some(true) && config.stop_on_catch_all {
        report
            .notes
            .push("candidate probing skipped (--stop-on-catch-all)".to_string());
        if let Some(sp) = spinner {
            sp.finish_with_message(format!("[{domain}] catch-all domain — candidate probing skipped"));
        }
        return Ok(report);
    }

    // ------------------------------------------------------------------
    // 3. Candidate scanning (round 0)
    // ------------------------------------------------------------------
    let locals = &config.local_parts;
    let slots: Mutex<Vec<Option<ProbeResult>>> = Mutex::new(vec![None; locals.len()]);
    let emitted: Mutex<Vec<bool>> = Mutex::new(vec![false; locals.len()]);
    let done = AtomicUsize::new(0);
    let emit: Mutex<EmitFn<'_>> = Mutex::new(on_result);

    let ctx = WorkerCtx {
        domain,
        hosts: &usable,
        locals,
        config,
        catch_all,
        attempts,
        timeouts,
        shutdown,
        retry_round: 0,
    };
    run_round(&ctx, (0..locals.len()).collect(), &slots, &emitted, &done, spinner.clone(), &emit).await;

    // ------------------------------------------------------------------
    // 4. Greylisting retries
    // ------------------------------------------------------------------
    for round in 1..=config.retry_greylist {
        let pending: Vec<usize> = slots
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| match slot {
                Some(result) if result.status == ProbeStatus::Temporary => Some(i),
                _ => None,
            })
            .collect();
        if pending.is_empty() {
            break;
        }
        set_phase(
            &spinner,
            format!(
                "[{domain}] retrying greylisted ({round}/{}) — waiting {}s",
                config.retry_greylist,
                config.retry_delay.as_secs()
            ),
        );
        interruptible_sleep(config.retry_delay, shutdown).await;
        if shutdown.load(Ordering::Relaxed) {
            report.interrupted = true;
            break;
        }
        let retry_ctx = WorkerCtx {
            retry_round: round,
            ..ctx
        };
        run_round(&retry_ctx, pending, &slots, &emitted, &done, spinner.clone(), &emit).await;
    }

    // ------------------------------------------------------------------
    // 5. Finalize: collect slots, stream anything still held
    // ------------------------------------------------------------------
    if shutdown.load(Ordering::Relaxed) {
        report.interrupted = true;
    }
    let slot_vec = slots.into_inner().unwrap();
    let emitted_vec = emitted.into_inner().unwrap();
    let unprobed = slot_vec.iter().filter(|slot| slot.is_none()).count();
    if unprobed > 0 {
        report
            .notes
            .push(format!("{unprobed} candidate(s) not probed (interrupted or mail host unreachable)"));
    }
    for (slot, was_emitted) in slot_vec.iter().zip(&emitted_vec) {
        if let (Some(result), false) = (slot, was_emitted) {
            let mut guard = emit.lock().unwrap();
            (*guard)(result);
        }
    }
    report.results = slot_vec.into_iter().flatten().collect();

    if let Some(sp) = spinner {
        let accepted = report
            .results
            .iter()
            .filter(|r| matches!(r.status, ProbeStatus::Accepted | ProbeStatus::AcceptedCatchAll))
            .count();
        let rejected = report.results.iter().filter(|r| r.status == ProbeStatus::Rejected).count();
        let other = report.results.len() - accepted - rejected;
        sp.finish_with_message(format!("[{domain}] {accepted} accepted · {rejected} rejected · {other} other"));
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Worker rounds
// ---------------------------------------------------------------------------

struct WorkerCtx<'a> {
    domain: &'a str,
    hosts: &'a [String],
    locals: &'a [String],
    config: &'a ResolvedConfig,
    catch_all: Option<bool>,
    attempts: &'a AtomicU64,
    timeouts: &'a AtomicU64,
    shutdown: &'a AtomicBool,
    retry_round: usize,
}

impl Clone for WorkerCtx<'_> {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for WorkerCtx<'_> {}

async fn run_round(
    ctx: &WorkerCtx<'_>,
    jobs: Vec<usize>,
    slots: &Mutex<Vec<Option<ProbeResult>>>,
    emitted: &Mutex<Vec<bool>>,
    done: &AtomicUsize,
    spinner: Option<ProgressBar>,
    emit: &Mutex<EmitFn<'_>>,
) {
    let queue = Mutex::new(VecDeque::from(jobs));
    let worker_count = ctx
        .config
        .concurrency
        .min(queue.lock().unwrap().len())
        .max(1);
    let mut workers = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        workers.push(run_worker(ctx, &queue, slots, emitted, done, spinner.clone(), emit));
    }
    futures::future::join_all(workers).await;
}

async fn run_worker(
    ctx: &WorkerCtx<'_>,
    queue: &Mutex<VecDeque<usize>>,
    slots: &Mutex<Vec<Option<ProbeResult>>>,
    emitted: &Mutex<Vec<bool>>,
    done: &AtomicUsize,
    spinner: Option<ProgressBar>,
    emit: &Mutex<EmitFn<'_>>,
) {
    let mut rng = rand::thread_rng();
    let mut prober = Prober::new(ctx.hosts, ctx.config, ctx.attempts, ctx.timeouts);
    let mut consecutive_failures = 0u32;

    while let Some(job) = {
        queue.lock().unwrap().pop_front()
    } {
        if ctx.shutdown.load(Ordering::Relaxed) {
            break;
        }
        let local = ctx.locals[job].as_str();
        let email = format!("{local}@{}", ctx.domain);
        let attempt_count = if ctx.retry_round == 0 {
            1
        } else {
            slots.lock().unwrap()[job]
                .as_ref()
                .map(|previous| previous.attempts + 1)
                .unwrap_or(1)
        };

        let outcome = prober.probe(&email, &mut rng, ctx.shutdown).await;
        let result = finalize_result(ctx.domain, local, outcome, ctx.catch_all, attempt_count);

        let final_now =
            result.status != ProbeStatus::Temporary || ctx.retry_round >= ctx.config.retry_greylist;
        slots.lock().unwrap()[job] = Some(result.clone());
        if final_now {
            {
                let mut guard = emit.lock().unwrap();
                (*guard)(&result);
            }
            emitted.lock().unwrap()[job] = true;
        }
        if ctx.retry_round == 0 {
            done.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(sp) = &spinner {
            let phase = if ctx.retry_round == 0 { "probing" } else { "retrying" };
            sp.set_message(format!(
                "[{}] {} {} ({}/{})",
                ctx.domain,
                phase,
                email,
                done.load(Ordering::Relaxed).min(ctx.locals.len()),
                ctx.locals.len()
            ));
        }

        if result.status == ProbeStatus::Error {
            consecutive_failures += 1;
            if consecutive_failures >= 3 {
                // Mail host looks unreachable — stop pulling jobs; leftovers are
                // reported as unprobed rather than burning the address space.
                break;
            }
        } else {
            consecutive_failures = 0;
        }
    }
    prober.finish().await;
}

// ---------------------------------------------------------------------------
// Connection prober (session reuse + reconnect/resume + MX failover)
// ---------------------------------------------------------------------------

struct ErrorInfo {
    stage: &'static str,
    message: String,
}

struct ProbeOutcome {
    reply: Option<(Stage, SmtpReply)>,
    error: Option<ErrorInfo>,
    latency: Option<Duration>,
    host: String,
}

struct Prober<'a> {
    hosts: &'a [String],
    config: &'a ResolvedConfig,
    attempts: &'a AtomicU64,
    timeouts: &'a AtomicU64,
    conn: Option<SmtpConnection>,
    host_idx: usize,
    used: usize,
    last_host: String,
    last_err: Option<(&'static str, String)>,
}

impl<'a> Prober<'a> {
    fn new(hosts: &'a [String], config: &'a ResolvedConfig, attempts: &'a AtomicU64, timeouts: &'a AtomicU64) -> Self {
        Self {
            hosts,
            config,
            attempts,
            timeouts,
            conn: None,
            host_idx: 0,
            used: 0,
            last_host: hosts.first().cloned().unwrap_or_default(),
            last_err: None,
        }
    }

    async fn cycle(&mut self) {
        self.drop_conn().await;
        self.used = 0;
        match connect_any(self.hosts, self.config, self.host_idx, self.attempts, self.timeouts).await {
            Ok((conn, idx)) => {
                self.host_idx = idx;
                self.last_host = self.hosts[idx].clone();
                self.conn = Some(conn);
            }
            Err(e) => {
                self.last_err = Some((e.stage().unwrap_or("tcp-connect"), e.to_string()));
            }
        }
    }

    async fn drop_conn(&mut self) {
        if let Some(mut conn) = self.conn.take() {
            conn.quit().await;
        }
    }

    async fn finish(&mut self) {
        self.drop_conn().await;
    }

    /// Probe one address. Reuses the current session until `max_rcpt_per_conn`
    /// probes have run on it, then reconnects. If the server drops the session
    /// mid-probe (421, timeout, reset), one transparent reconnect-and-resume
    /// is attempted for the same candidate before giving up.
    async fn probe(&mut self, email: &str, rng: &mut impl Rng, shutdown: &AtomicBool) -> ProbeOutcome {
        sleep_jitter(self.config.delay_ms, self.config.jitter_ms, rng, shutdown).await;
        for _attempt in 0..2 {
            if self.conn.is_none() || self.used >= self.config.max_rcpt_per_conn {
                self.cycle().await;
            }
            let Some(conn) = self.conn.as_mut() else {
                return self.error_outcome();
            };
            let started = Instant::now();
            match conn.probe_rcpt(&self.config.mail_from, email).await {
                Ok((stage, reply)) => {
                    let latency = started.elapsed();
                    self.used += 1;
                    let keep = reply.code != 421 && matches!(conn.rset().await, Ok(r) if r.code == 250);
                    if !keep {
                        self.drop_conn().await;
                    }
                    return ProbeOutcome {
                        reply: Some((stage, reply)),
                        error: None,
                        latency: Some(latency),
                        host: self.last_host.clone(),
                    };
                }
                Err(e) => {
                    self.last_err = Some((e.stage().unwrap_or("rcpt-to"), e.to_string()));
                    self.drop_conn().await;
                }
            }
        }
        self.error_outcome()
    }

    fn error_outcome(&self) -> ProbeOutcome {
        let (stage, message) = self
            .last_err
            .clone()
            .unwrap_or_else(|| ("tcp-connect", "no usable connection to any mail exchanger".to_string()));
        ProbeOutcome {
            reply: None,
            error: Some(ErrorInfo { stage, message }),
            latency: None,
            host: self.last_host.clone(),
        }
    }
}

async fn connect_any(
    hosts: &[String],
    config: &ResolvedConfig,
    preferred: usize,
    attempts: &AtomicU64,
    timeouts: &AtomicU64,
) -> Result<(SmtpConnection, usize), SmtpError> {
    let count = hosts.len();
    let mut last: Option<SmtpError> = None;
    for offset in 0..count {
        let idx = (preferred + offset) % count;
        attempts.fetch_add(1, Ordering::Relaxed);
        let cfg = ConnectConfig {
            host: hosts[idx].clone(),
            port: config.port,
            timeout: config.timeout,
            starttls: config.starttls,
            insecure: config.insecure,
            ehlo_name: if config.random_ehlo { random_ehlo_name() } else { config.ehlo.clone() },
            implicit_tls: config.port == 465,
        };
        match SmtpConnection::connect(&cfg, next_conn_id()).await {
            Ok(conn) => {
                tracing::debug!(
                    host = %hosts[idx],
                    server = %conn.remote_name,
                    caps = %conn.capabilities.join(","),
                    tls = ?conn.tls.as_ref().map(|t| (t.version.as_str(), t.verified)),
                    "SMTP session established"
                );
                return Ok((conn, idx));
            }
            Err(e) => {
                if e.is_connect_timeout() {
                    timeouts.fetch_add(1, Ordering::Relaxed);
                }
                tracing::debug!(host = %hosts[idx], error = %e, "connection attempt failed");
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| SmtpError::Protocol {
        stage: "tcp-connect",
        message: "no mail hosts available".to_string(),
    }))
}

fn random_ehlo_name() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 6];
    rng.fill(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("mta-{hex}.probe.local")
}

// ---------------------------------------------------------------------------
// Classification & result construction
// ---------------------------------------------------------------------------

fn finalize_result(
    domain: &str,
    local: &str,
    outcome: ProbeOutcome,
    catch_all: Option<bool>,
    attempts: u16,
) -> ProbeResult {
    let email = format!("{local}@{domain}");
    match outcome.reply {
        Some((stage, reply)) => {
            let status = classify(stage, &reply, catch_all);
            let message = if stage == Stage::MailFrom {
                format!("rejected at MAIL FROM: {}", reply.summary())
            } else {
                reply.summary()
            };
            ProbeResult {
                domain: domain.to_string(),
                local_part: local.to_string(),
                email,
                status,
                smtp_code: Some(reply.code),
                enhanced_code: reply.enhanced.map(|e| e.to_string()),
                stage: Some(stage.as_str().to_string()),
                message,
                mx_host: outcome.host,
                attempts,
                latency_ms: outcome.latency.map(|d| d.as_millis() as u64),
            }
        }
        None => {
            let error = outcome.error.unwrap_or_else(|| ErrorInfo {
                stage: "probe",
                message: "unknown failure".to_string(),
            });
            ProbeResult {
                domain: domain.to_string(),
                local_part: local.to_string(),
                email,
                status: ProbeStatus::Error,
                smtp_code: None,
                enhanced_code: None,
                stage: Some(error.stage.to_string()),
                message: error.message,
                mx_host: outcome.host,
                attempts,
                latency_ms: None,
            }
        }
    }
}

/// Map an SMTP reply (plus its stage and the domain's catch-all state) to a
/// verdict. Uses both the 3-digit code and the RFC 3463 enhanced code.
fn classify(stage: Stage, reply: &SmtpReply, catch_all: Option<bool>) -> ProbeStatus {
    use ProbeStatus::{Accepted, AcceptedCatchAll, Indeterminate, PolicyBlocked, Rejected, Temporary};

    if stage == Stage::MailFrom {
        // Rejected before we even named a recipient: sender-based policy
        // (SPF, blocklist, anti-enumeration) or a transient throttle.
        return if reply.code >= 500 { PolicyBlocked } else { Temporary };
    }

    match reply.code {
        250 | 251 if catch_all == Some(true) => AcceptedCatchAll,
        250 | 251 => Accepted,
        252 => Indeterminate,
        400..=499 => Temporary,
        500..=599 => {
            if let Some(esc) = reply.enhanced {
                if esc.class == 5 && esc.subject == 7 {
                    return PolicyBlocked; // 5.7.x: policy / refused / blocklist
                }
                if esc.class == 5 && esc.subject == 1 && matches!(esc.detail, 1 | 2 | 10) {
                    return Rejected; // 5.1.1 / 5.1.2 / 5.1.10: bad destination mailbox
                }
            }
            const POLICY_HINTS: &[&str] = &[
                "policy", "blocked", "block list", "blacklist", "rbl", "dnsbl", "spam", "abuse", "not permitted",
                "unauthorized", "no relaying", "reputation", "rejected by recipient",
            ];
            let text = reply.text.to_lowercase();
            if POLICY_HINTS.iter().any(|hint| text.contains(hint)) {
                PolicyBlocked
            } else {
                // Unknown 5xx at RCPT defaults to "mailbox rejected".
                Rejected
            }
        }
        _ => Indeterminate,
    }
}

// ---------------------------------------------------------------------------
// Rate limiting & interruptible sleeping
// ---------------------------------------------------------------------------

async fn sleep_jitter(delay_ms: u64, jitter_ms: u64, rng: &mut impl Rng, shutdown: &AtomicBool) {
    let base = delay_ms as i64;
    let jitter = if jitter_ms > 0 {
        rng.gen_range(-(jitter_ms as i64)..=(jitter_ms as i64))
    } else {
        0
    };
    let total = (base + jitter).clamp(0, i64::from(u32::MAX)) as u64;
    interruptible_sleep(Duration::from_millis(total), shutdown).await;
}

async fn interruptible_sleep(duration: Duration, shutdown: &AtomicBool) {
    let step = Duration::from_millis(100);
    let mut remaining = duration;
    while !remaining.is_zero() {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let chunk = remaining.min(step);
        tokio::time::sleep(chunk).await;
        remaining = remaining.saturating_sub(chunk);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smtp::parser::parse_reply;

    fn reply(lines: &[&str]) -> SmtpReply {
        parse_reply(&lines.iter().map(|l| l.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn accepted() {
        assert_eq!(classify(Stage::RcptTo, &reply(&["250 2.1.5 Ok"]), None), ProbeStatus::Accepted);
        assert_eq!(classify(Stage::RcptTo, &reply(&["251 User not local; will forward"]), None), ProbeStatus::Accepted);
    }

    #[test]
    fn accepted_catch_all() {
        assert_eq!(
            classify(Stage::RcptTo, &reply(&["250 Ok"]), Some(true)),
            ProbeStatus::AcceptedCatchAll
        );
        assert_eq!(classify(Stage::RcptTo, &reply(&["250 Ok"]), Some(false)), ProbeStatus::Accepted);
    }

    #[test]
    fn unknown_mailbox() {
        assert_eq!(
            classify(Stage::RcptTo, &reply(&["550 5.1.1 <x@y.z>: Recipient address rejected: User unknown"]), None),
            ProbeStatus::Rejected
        );
        assert_eq!(
            classify(Stage::RcptTo, &reply(&["550 5.1.10 Requested action not taken: mailbox unavailable"]), None),
            ProbeStatus::Rejected
        );
    }

    #[test]
    fn policy_blocks() {
        assert_eq!(
            classify(Stage::RcptTo, &reply(&["550 5.7.1 Message rejected: Email address is not authorized"]), None),
            ProbeStatus::PolicyBlocked
        );
        assert_eq!(
            classify(Stage::RcptTo, &reply(&["554 Blocked by spamhaus RBL"]), None),
            ProbeStatus::PolicyBlocked
        );
        assert_eq!(
            classify(Stage::MailFrom, &reply(&["550 5.7.1 Sender address rejected"]), None),
            ProbeStatus::PolicyBlocked
        );
    }

    #[test]
    fn temporary() {
        assert_eq!(
            classify(Stage::RcptTo, &reply(&["450 4.7.1 Greylisted, please try again later"]), None),
            ProbeStatus::Temporary
        );
        assert_eq!(
            classify(Stage::RcptTo, &reply(&["452 4.2.2 Mailbox full"]), None),
            ProbeStatus::Temporary
        );
        assert_eq!(
            classify(Stage::MailFrom, &reply(&["450 4.3.2 Service temporarily unavailable"]), None),
            ProbeStatus::Temporary
        );
    }

    #[test]
    fn indeterminate() {
        assert_eq!(
            classify(Stage::RcptTo, &reply(&["252 Cannot VRFY user, but will accept message"]), None),
            ProbeStatus::Indeterminate
        );
    }

    #[test]
    fn plain_5xx_defaults_to_rejected() {
        assert_eq!(
            classify(Stage::RcptTo, &reply(&["550 Requested action not taken: mailbox unavailable"]), None),
            ProbeStatus::Rejected
        );
    }
}

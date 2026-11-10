//! Integration tests: the full scanner against an in-process scripted SMTP
//! server. No network access beyond loopback TCP is required (the fake
//! domain `probe.test` is a reserved TLD, so DNS lookups answer NXDOMAIN
//! immediately).

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use smtp_probe::cli::ResolvedConfig;
use smtp_probe::output::Format;
use smtp_probe::scanner::{self, ProbeResult, ProbeStatus, ScanOutcome};
use smtp_probe::smtp::StarttlsMode;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const DOMAIN: &str = "probe.test";

// ---------------------------------------------------------------------------
// Scripted server
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct ServerMode {
    /// Accept every address, including the random catch-all probes.
    catch_all: bool,
    /// Answer this many RCPTs per connection, then drop without replying.
    drop_after_rcpt: Option<usize>,
}

#[derive(Default)]
struct ServerState {
    connections: usize,
    rcpt_seen: Vec<String>,
}

async fn spawn_server(mode: ServerMode) -> (u16, Arc<Mutex<ServerState>>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    let state = Arc::new(Mutex::new(ServerState::default()));
    let state_for_task = state.clone();

    let server = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let mode = mode.clone();
            let state = state_for_task.clone();
            tokio::spawn(handle_connection(stream, mode, state));
        }
    });
    (port, state, server)
}

async fn handle_connection(stream: TcpStream, mode: ServerMode, state: Arc<Mutex<ServerState>>) {
    state.lock().unwrap().connections += 1;

    let mut stream = stream;
    let _ = stream
        .write_all(b"220 fake.local ESMTP smtp-probe integration test\r\n")
        .await;
    let (read_half, mut write_half) = stream.split();
    let mut lines = BufReader::new(read_half).lines();
    let mut rcpt_on_connection = 0usize;

    while let Ok(Some(line)) = lines.next_line().await {
        let upper = line.to_uppercase();
        let reply: Option<String> = if upper.starts_with("EHLO") {
            Some("250-fake.local\r\n250-SIZE 35882577\r\n250 ENHANCEDSTATUSCODES\r\n".to_string())
        } else if upper.starts_with("HELO") {
            Some("250 fake.local\r\n".to_string())
        } else if upper.starts_with("MAIL FROM:") {
            Some("250 2.1.0 Ok\r\n".to_string())
        } else if upper.starts_with("RCPT TO:") {
            rcpt_on_connection += 1;
            let address = extract_address(&line).unwrap_or_default();
            let attempts = {
                let mut guard = state.lock().unwrap();
                guard.rcpt_seen.push(address.clone());
                guard
                    .rcpt_seen
                    .iter()
                    .filter(|seen| **seen == address)
                    .count()
            };
            // Answer the configured number of probes, then simulate the server
            // dropping the session mid-batch (no reply, socket closed).
            if let Some(limit) = mode.drop_after_rcpt
                && rcpt_on_connection > limit
            {
                return;
            }
            Some(reply_for(&address, &mode, attempts))
        } else if upper.starts_with("RSET") {
            Some("250 2.1.0 Ok\r\n".to_string())
        } else if upper.starts_with("QUIT") {
            let _ = write_half.write_all(b"221 2.0.0 Bye\r\n").await;
            return;
        } else {
            Some("500 5.5.2 Unrecognized command\r\n".to_string())
        };

        if let Some(reply) = reply
            && write_half.write_all(reply.as_bytes()).await.is_err()
        {
            return;
        }
    }
}

fn extract_address(line: &str) -> Option<String> {
    let rest = line.strip_prefix("RCPT TO:")?.trim();
    let rest = rest.strip_prefix('<').unwrap_or(rest);
    let end = rest.find('>').unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

fn reply_for(address: &str, mode: &ServerMode, attempts: usize) -> String {
    let local = address.split('@').next().unwrap_or_default();

    // Catch-all probes use random `<uuid>.probe` local parts.
    if local.ends_with(".probe") {
        return if mode.catch_all {
            "250 2.1.5 Ok\r\n".to_string()
        } else {
            "550 5.1.1 User unknown\r\n".to_string()
        };
    }

    // Candidates named good1..goodN all exist.
    if local.starts_with("good") {
        return "250 2.1.5 Ok\r\n".to_string();
    }

    match local {
        "bad" => "550 5.1.1 <bad@probe.test> Recipient address rejected: User unknown\r\n",
        "maybe" => "252 2.1.5 Cannot VRFY user, but will accept message\r\n",
        "blocked" => "550 5.7.1 Message rejected due to local policy\r\n",
        "grey" => {
            if attempts <= 1 {
                "450 4.7.1 Greylisted, please try again later\r\n"
            } else {
                "250 2.1.5 Ok\r\n"
            }
        }
        _ => "550 5.1.1 User unknown\r\n",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_config(port: u16, locals: &[&str]) -> ResolvedConfig {
    ResolvedConfig {
        targets: vec![DOMAIN.to_string()],
        local_parts: locals.iter().map(|local| local.to_string()).collect(),
        mail_from: "probe@example.com".to_string(),
        ehlo: "tester.local".to_string(),
        random_ehlo: false,
        port,
        mx_host: Some("127.0.0.1".to_string()),
        mx_failover: true,
        starttls: StarttlsMode::Disabled,
        insecure: false,
        // Nothing listens on loopback :53 — TXT lookups fail instantly instead
        // of letting a slow system resolver stall every test.
        dns_server: Some("127.0.0.1".parse().unwrap()),
        concurrency: 1,
        max_rcpt_per_conn: 5,
        delay_ms: 0,
        jitter_ms: 0,
        timeout: Duration::from_secs(5),
        catch_all_probes: 1,
        stop_on_catch_all: false,
        retry_greylist: 0,
        retry_delay: Duration::ZERO,
        format: Format::Table,
        only_accepted: false,
    }
}

async fn run_scan(config: &ResolvedConfig) -> (ScanOutcome, Vec<ProbeResult>) {
    let mut streamed = Vec::new();
    let shutdown = Arc::new(AtomicBool::new(false));
    let outcome = scanner::run(config, None, shutdown, &mut |result: &ProbeResult| {
        streamed.push(result.clone())
    })
    .await
    .expect("scan completes");
    (outcome, streamed)
}

fn status_of(outcome: &ScanOutcome, local: &str) -> ProbeStatus {
    outcome.reports[0]
        .results
        .iter()
        .find(|result| result.local_part == local)
        .map(|result| result.status)
        .unwrap_or_else(|| panic!("no result for {local}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn classifies_replies_end_to_end() {
    let (port, state, server) = spawn_server(ServerMode::default()).await;
    let (outcome, streamed) =
        run_scan(&test_config(port, &["good1", "bad", "maybe", "blocked"])).await;

    let report = &outcome.reports[0];
    assert_eq!(report.domain, DOMAIN);
    assert_eq!(report.catch_all, Some(false));
    assert_eq!(report.results.len(), 4);

    assert_eq!(status_of(&outcome, "good1"), ProbeStatus::Accepted);
    assert_eq!(status_of(&outcome, "bad"), ProbeStatus::Rejected);
    assert_eq!(status_of(&outcome, "maybe"), ProbeStatus::Indeterminate);
    assert_eq!(status_of(&outcome, "blocked"), ProbeStatus::PolicyBlocked);

    // SMTP details are propagated into the results.
    let bad = report
        .results
        .iter()
        .find(|r| r.local_part == "bad")
        .unwrap();
    assert_eq!(bad.smtp_code, Some(550));
    assert_eq!(bad.enhanced_code.as_deref(), Some("5.1.1"));
    assert_eq!(bad.attempts, 1);
    assert!(bad.message.contains("User unknown"));

    // Everything was final on the first pass, so all rows were streamed.
    assert_eq!(streamed.len(), 4);

    // Catch-all prober + candidate worker = exactly two sessions.
    assert_eq!(state.lock().unwrap().connections, 2);
    server.abort();
}

#[tokio::test]
async fn sessions_are_reused_via_rset() {
    let (port, state, server) = spawn_server(ServerMode::default()).await;
    let mut config = test_config(port, &["good1", "good2", "good3", "good4"]);
    config.catch_all_probes = 0; // skip catch-all phase: worker session only
    config.max_rcpt_per_conn = 2; // reconnect after two probes per session

    let (outcome, _) = run_scan(&config).await;

    // All four candidates accepted…
    assert_eq!(outcome.reports[0].results.len(), 4);
    assert!(
        outcome.reports[0]
            .results
            .iter()
            .all(|r| r.status == ProbeStatus::Accepted)
    );
    // …but only two sessions were opened (4 probes / 2 per session).
    assert_eq!(state.lock().unwrap().connections, 2);
    server.abort();
}

#[tokio::test]
async fn dropped_sessions_are_reconnected_and_resumed() {
    let mode = ServerMode {
        catch_all: false,
        drop_after_rcpt: Some(2), // every session answers two probes, then dies
    };
    let (port, state, server) = spawn_server(mode).await;
    let mut config = test_config(port, &["good1", "good2", "good3", "good4"]);
    config.catch_all_probes = 0;
    config.max_rcpt_per_conn = 10; // the *server* enforces the drop, not us

    let (outcome, _) = run_scan(&config).await;

    // No candidate is lost: the scanner reconnects and resumes from the
    // failed one. Two answered probes per connection → two connections.
    assert_eq!(outcome.reports[0].results.len(), 4);
    assert!(
        outcome.reports[0]
            .results
            .iter()
            .all(|r| r.status == ProbeStatus::Accepted)
    );
    assert_eq!(state.lock().unwrap().connections, 2);
    server.abort();
}

#[tokio::test]
async fn greylisted_candidates_are_retried() {
    let (port, state, server) = spawn_server(ServerMode::default()).await;
    let mut config = test_config(port, &["grey"]);
    config.catch_all_probes = 0;
    config.retry_greylist = 1;
    config.retry_delay = Duration::ZERO;

    let (outcome, streamed) = run_scan(&config).await;

    assert_eq!(status_of(&outcome, "grey"), ProbeStatus::Accepted);
    let grey = outcome.reports[0]
        .results
        .iter()
        .find(|r| r.local_part == "grey")
        .unwrap();
    assert_eq!(grey.attempts, 2);
    // The temporary first-pass result was held back and only the final
    // accepted verdict was streamed once.
    assert_eq!(streamed.len(), 1);
    assert_eq!(streamed[0].status, ProbeStatus::Accepted);
    // The server really saw the address twice.
    assert_eq!(
        state
            .lock()
            .unwrap()
            .rcpt_seen
            .iter()
            .filter(|a| a.contains("grey"))
            .count(),
        2
    );
    server.abort();
}

#[tokio::test]
async fn greylisted_candidates_stay_temporary_without_retries() {
    let (port, _state, server) = spawn_server(ServerMode::default()).await;
    let mut config = test_config(port, &["grey"]);
    config.catch_all_probes = 0;
    config.retry_greylist = 0;

    let (outcome, streamed) = run_scan(&config).await;

    assert_eq!(status_of(&outcome, "grey"), ProbeStatus::Temporary);
    assert_eq!(streamed.len(), 1);
    server.abort();
}

#[tokio::test]
async fn catch_all_domains_flag_accepted_candidates() {
    let mode = ServerMode {
        catch_all: true,
        drop_after_rcpt: None,
    };
    let (port, _state, server) = spawn_server(mode).await;
    let (outcome, _) = run_scan(&test_config(port, &["good1"])).await;

    let report = &outcome.reports[0];
    assert_eq!(report.catch_all, Some(true));
    assert_eq!(status_of(&outcome, "good1"), ProbeStatus::AcceptedCatchAll);
    server.abort();
}

#[tokio::test]
async fn stop_on_catch_all_skips_candidates() {
    let mode = ServerMode {
        catch_all: true,
        drop_after_rcpt: None,
    };
    let (port, _state, server) = spawn_server(mode).await;
    let mut config = test_config(port, &["good1", "good2"]);
    config.stop_on_catch_all = true;

    let (outcome, streamed) = run_scan(&config).await;

    let report = &outcome.reports[0];
    assert_eq!(report.catch_all, Some(true));
    assert!(report.results.is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("--stop-on-catch-all"))
    );
    assert!(streamed.is_empty());
    server.abort();
}

#[tokio::test]
async fn mx_records_and_provider_land_in_the_report() {
    let (port, _state, server) = spawn_server(ServerMode::default()).await;
    let (outcome, _) = run_scan(&test_config(port, &["good1"])).await;

    let report = &outcome.reports[0];
    // --mx-host override is reflected as a single MX entry.
    assert_eq!(report.mx_records.len(), 1);
    assert_eq!(report.mx_records[0].exchange, "127.0.0.1");
    assert_eq!(report.probed_via.as_deref(), Some("127.0.0.1"));
    assert!(!outcome.interrupted);
    server.abort();
}

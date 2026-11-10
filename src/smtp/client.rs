//! Async SMTP transport: TCP connect with timeouts, optional implicit TLS
//! (port 465) or STARTTLS upgrade, multi-line reply reading, and the
//! `MAIL FROM` / `RCPT TO` / `RSET` probing primitives used by the scanner.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::smtp::parser::{self, ParseError, SmtpReply};
use crate::smtp::StarttlsMode;

/// Tracing target used for raw SMTP transcript lines (shown with `-v`).
pub const TRANSCRIPT_TARGET: &str = "smtp_probe::transcript";

static CONN_SEQ: AtomicU64 = AtomicU64::new(1);

/// Allocate a monotonically increasing connection id for transcript prefixes.
pub fn next_conn_id() -> u64 {
    CONN_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Protocol stage a failure (or reply) occurred at.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Establishing the TCP connection.
    TcpConnect,
    /// The initial `220` greeting.
    Banner,
    /// `EHLO` / `HELO` exchange.
    Ehlo,
    /// The `STARTTLS` negotiation command.
    StartTls,
    /// The TLS handshake itself.
    TlsHandshake,
    /// `MAIL FROM:<...>`.
    MailFrom,
    /// `RCPT TO:<...>`.
    RcptTo,
    /// `RSET` between probes inside a session.
    Rset,
    /// `QUIT`.
    Quit,
}

impl Stage {
    /// Stable, machine-friendly stage name.
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::TcpConnect => "tcp-connect",
            Stage::Banner => "banner",
            Stage::Ehlo => "ehlo",
            Stage::StartTls => "starttls",
            Stage::TlsHandshake => "tls-handshake",
            Stage::MailFrom => "mail-from",
            Stage::RcptTo => "rcpt-to",
            Stage::Rset => "rset",
            Stage::Quit => "quit",
        }
    }
}

/// Transport-level and protocol-level failures raised by [`SmtpConnection`].
#[derive(Debug, Error)]
pub enum SmtpError {
    /// The outbound TCP connection timed out (possible port-25 egress block).
    #[error("TCP connect to {host}:{port} timed out after {secs}s (outbound port {port} may be blocked)")]
    ConnectTimeout {
        /// Host that was attempted.
        host: String,
        /// Port that was attempted.
        port: u16,
        /// Timeout budget in seconds.
        secs: u64,
    },
    /// The outbound TCP connection failed for a non-timeout reason (refused, DNS, …).
    #[error("TCP connect to {host}:{port} failed: {source}")]
    Connect {
        /// Host that was attempted.
        host: String,
        /// Port that was attempted.
        port: u16,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A read or write exceeded the per-operation timeout.
    #[error("timed out during {stage} after {secs}s")]
    Timeout {
        /// Stage where the timeout occurred.
        stage: &'static str,
        /// Timeout budget in seconds.
        secs: u64,
    },
    /// The server closed the connection (EOF or reset).
    #[error("connection closed by server during {stage}")]
    Closed {
        /// Stage where the connection was lost.
        stage: &'static str,
    },
    /// `--starttls required` was set but the server does not advertise STARTTLS.
    #[error("STARTTLS required but the server does not offer it")]
    StarttlsUnavailable,
    /// The TLS handshake failed.
    #[error("TLS handshake failed: {0}")]
    Tls(String),
    /// The server sent something that is not valid SMTP.
    #[error("SMTP protocol error during {stage}: {message}")]
    Protocol {
        /// Stage where the protocol violation happened.
        stage: &'static str,
        /// Description of the violation.
        message: String,
    },
    /// The server rejected a command with a permanent or transient code.
    #[error("rejected during {stage}: {code} {text}")]
    Rejected {
        /// Stage that was rejected.
        stage: &'static str,
        /// SMTP reply code.
        code: u16,
        /// Reply text.
        text: String,
    },
    /// Generic I/O failure.
    #[error("I/O error during {stage}: {source}")]
    Io {
        /// Stage where the I/O error occurred.
        stage: &'static str,
        /// Underlying error.
        source: std::io::Error,
    },
}

impl SmtpError {
    /// True when this failure was an outbound TCP connect timeout. The scanner
    /// aggregates these for the "port 25 blocked" heuristic (exit code 2).
    pub fn is_connect_timeout(&self) -> bool {
        matches!(self, SmtpError::ConnectTimeout { .. })
    }

    /// The protocol stage this error occurred at, when known.
    pub fn stage(&self) -> Option<&'static str> {
        match self {
            SmtpError::ConnectTimeout { .. } | SmtpError::Connect { .. } => Some(Stage::TcpConnect.as_str()),
            SmtpError::Timeout { stage, .. }
            | SmtpError::Closed { stage }
            | SmtpError::Protocol { stage, .. }
            | SmtpError::Rejected { stage, .. }
            | SmtpError::Io { stage, .. } => Some(stage),
            SmtpError::StarttlsUnavailable => Some(Stage::StartTls.as_str()),
            SmtpError::Tls(_) => Some(Stage::TlsHandshake.as_str()),
        }
    }
}

/// Everything needed to establish one SMTP session.
#[derive(Clone, Debug)]
pub struct ConnectConfig {
    /// Hostname or IP literal of the mail server.
    pub host: String,
    /// TCP port (25, 587 submission, 465 implicit TLS).
    pub port: u16,
    /// Per-operation timeout (connect, read, write, handshake).
    pub timeout: Duration,
    /// STARTTLS policy.
    pub starttls: StarttlsMode,
    /// Skip TLS certificate verification (`--insecure`).
    pub insecure: bool,
    /// Identity announced in `EHLO`.
    pub ehlo_name: String,
    /// Wrap the socket in TLS before reading the banner (port 465 / SMTPS).
    pub implicit_tls: bool,
}

/// Information about the negotiated TLS layer.
#[derive(Debug, Clone)]
pub struct TlsSummary {
    /// Negotiated protocol version (e.g. `TLSv1.3`).
    pub version: String,
    /// SNI/host the certificate was presented for.
    pub host: String,
    /// Whether the certificate chain was actually verified.
    pub verified: bool,
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Stream::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Stream::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Stream::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Stream::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// A live SMTP session against one mail exchanger.
pub struct SmtpConnection {
    reader: BufReader<Stream>,
    timeout: Duration,
    conn_id: u64,
    /// Capabilities from the most recent successful `EHLO` (upper-cased keywords).
    pub capabilities: Vec<String>,
    /// The server's own name from its banner, when advertised.
    pub remote_name: String,
    /// Details of the TLS layer, when the session is encrypted.
    pub tls: Option<TlsSummary>,
}

impl SmtpConnection {
    /// Open a session: TCP → (implicit TLS) → banner → `EHLO` → optional
    /// `STARTTLS` → `EHLO` again, following `ConnectConfig`.
    ///
    /// # Errors
    ///
    /// Returns [`SmtpError`] describing the failing stage.
    pub async fn connect(cfg: &ConnectConfig, conn_id: u64) -> Result<SmtpConnection, SmtpError> {
        let tcp = tcp_connect(cfg).await?;

        let mut reader: BufReader<Stream>;
        let mut tls_summary: Option<TlsSummary> = None;

        if cfg.implicit_tls {
            let (stream, summary) = tls_upgrade(tcp, cfg, conn_id).await?;
            tls_summary = Some(summary);
            reader = BufReader::new(Stream::Tls(Box::new(stream)));
        } else {
            reader = BufReader::new(Stream::Plain(tcp));
        }

        let banner = read_reply_from(&mut reader, Stage::Banner, cfg.timeout, conn_id).await?;
        if banner.code >= 400 {
            return Err(SmtpError::Rejected {
                stage: Stage::Banner.as_str(),
                code: banner.code,
                text: banner.summary(),
            });
        }
        let remote_name = banner
            .lines
            .first()
            .and_then(|line| line.get(4..))
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or_default()
            .to_string();

        let mut capabilities = ehlo_exchange_on(&mut reader, cfg, conn_id).await?;

        if !cfg.implicit_tls && cfg.starttls != StarttlsMode::Disabled {
            let offered = capabilities.iter().any(|cap| cap == "STARTTLS");
            if offered {
                send_line(reader.get_mut(), "STARTTLS", Stage::StartTls, cfg.timeout, conn_id).await?;
                let reply = read_reply_from(&mut reader, Stage::StartTls, cfg.timeout, conn_id).await?;
                if reply.code == 220 {
                    let plain = match reader.into_inner() {
                        Stream::Plain(stream) => stream,
                        Stream::Tls(_) => {
                            return Err(SmtpError::Protocol {
                                stage: Stage::StartTls.as_str(),
                                message: "STARTTLS offered on an already-encrypted session".to_string(),
                            })
                        }
                    };
                    let (stream, summary) = tls_upgrade(plain, cfg, conn_id).await?;
                    tls_summary = Some(summary);
                    reader = BufReader::new(Stream::Tls(Box::new(stream)));
                    // RFC 3207 §4.1: knowledge from the pre-TLS EHLO must be discarded.
                    capabilities = ehlo_exchange_on(&mut reader, cfg, conn_id).await?;
                } else if cfg.starttls == StarttlsMode::Required {
                    return Err(SmtpError::Rejected {
                        stage: Stage::StartTls.as_str(),
                        code: reply.code,
                        text: reply.summary(),
                    });
                }
                // Opportunistic + failed STARTTLS negotiation: continue in plain text.
            } else if cfg.starttls == StarttlsMode::Required {
                return Err(SmtpError::StarttlsUnavailable);
            }
        }

        tracing::debug!(
            target: TRANSCRIPT_TARGET,
            conn = conn_id,
            "session ready: server={} caps=[{}] tls={}",
            if remote_name.is_empty() { "?" } else { &remote_name },
            capabilities.join(","),
            tls_summary
                .as_ref()
                .map(|t| format!("{} via {} (certificate verified: {})", t.version, t.host, t.verified))
                .unwrap_or_else(|| "plain text".to_string())
        );

        Ok(SmtpConnection {
            reader,
            timeout: cfg.timeout,
            conn_id,
            capabilities,
            remote_name,
            tls: tls_summary,
        })
    }

    /// Send a command and read its complete (possibly multi-line) reply.
    ///
    /// # Errors
    ///
    /// Returns [`SmtpError`] on transport failure or timeout.
    pub async fn cmd(&mut self, line: &str, stage: Stage) -> Result<SmtpReply, SmtpError> {
        send_line(self.reader.get_mut(), line, stage, self.timeout, self.conn_id).await?;
        read_reply_from(&mut self.reader, stage, self.timeout, self.conn_id).await
    }

    /// Probe one recipient: `MAIL FROM` first (so sender-stage policy
    /// rejections are attributed correctly), then `RCPT TO`. The reply stage
    /// tells which command produced it.
    ///
    /// # Errors
    ///
    /// Returns [`SmtpError`] on transport failure; SMTP-level rejections are
    /// returned as successful replies with 4xx/5xx codes.
    pub async fn probe_rcpt(&mut self, mail_from: &str, rcpt_to: &str) -> Result<(Stage, SmtpReply), SmtpError> {
        let mail = self.cmd(&format!("MAIL FROM:<{mail_from}>"), Stage::MailFrom).await?;
        if mail.code >= 400 {
            return Ok((Stage::MailFrom, mail));
        }
        let rcpt = self.cmd(&format!("RCPT TO:<{rcpt_to}>"), Stage::RcptTo).await?;
        Ok((Stage::RcptTo, rcpt))
    }

    /// Reset the mail transaction so the session can probe the next candidate.
    ///
    /// # Errors
    ///
    /// Returns [`SmtpError`] on transport failure or timeout.
    pub async fn rset(&mut self) -> Result<SmtpReply, SmtpError> {
        self.cmd("RSET", Stage::Rset).await
    }

    /// Politely close the session. Errors are intentionally swallowed.
    pub async fn quit(&mut self) {
        let _ = self.cmd("QUIT", Stage::Quit).await;
    }
}

// ---------------------------------------------------------------------------
// Free helpers (used before the SmtpConnection struct is assembled)
// ---------------------------------------------------------------------------

async fn tcp_connect(cfg: &ConnectConfig) -> Result<TcpStream, SmtpError> {
    let secs = cfg.timeout.as_secs().max(1);
    let fut = TcpStream::connect((cfg.host.as_str(), cfg.port));
    match tokio::time::timeout(cfg.timeout, fut).await {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            Ok(stream)
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::TimedOut => Err(SmtpError::ConnectTimeout {
            host: cfg.host.clone(),
            port: cfg.port,
            secs,
        }),
        Ok(Err(e)) => Err(SmtpError::Connect {
            host: cfg.host.clone(),
            port: cfg.port,
            source: e,
        }),
        Err(_) => Err(SmtpError::ConnectTimeout {
            host: cfg.host.clone(),
            port: cfg.port,
            secs,
        }),
    }
}

async fn send_line(stream: &mut Stream, line: &str, stage: Stage, timeout: Duration, conn_id: u64) -> Result<(), SmtpError> {
    tracing::debug!(target: TRANSCRIPT_TARGET, conn = conn_id, ">>> {line}");
    let framed = format!("{line}\r\n");
    let write = async {
        stream.write_all(framed.as_bytes()).await?;
        stream.flush().await
    };
    match tokio::time::timeout(timeout, write).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(map_io_error(e, stage)),
        Err(_) => Err(SmtpError::Timeout {
            stage: stage.as_str(),
            secs: timeout.as_secs().max(1),
        }),
    }
}

async fn read_reply_from(
    reader: &mut BufReader<Stream>,
    stage: Stage,
    timeout: Duration,
    conn_id: u64,
) -> Result<SmtpReply, SmtpError> {
    let mut lines: Vec<String> = Vec::new();
    loop {
        let mut buf: Vec<u8> = Vec::new();
        match tokio::time::timeout(timeout, reader.read_until(b'\n', &mut buf)).await {
            Ok(Ok(0)) => {
                tracing::debug!(target: TRANSCRIPT_TARGET, conn = conn_id, "<<< [connection closed]");
                return Err(SmtpError::Closed {
                    stage: stage.as_str(),
                });
            }
            Ok(Ok(_)) => {
                let line = String::from_utf8_lossy(&buf)
                    .trim_end_matches(['\r', '\n'])
                    .to_string();
                tracing::debug!(target: TRANSCRIPT_TARGET, conn = conn_id, "<<< {line}");
                let final_line = is_final_line(&line);
                lines.push(line);
                if final_line {
                    break;
                }
            }
            Ok(Err(e)) => return Err(map_io_error(e, stage)),
            Err(_) => {
                return Err(SmtpError::Timeout {
                    stage: stage.as_str(),
                    secs: timeout.as_secs().max(1),
                })
            }
        }
    }

    parser::parse_reply(&lines).map_err(|e| match e {
        ParseError::Incomplete => SmtpError::Closed {
            stage: stage.as_str(),
        },
        ParseError::Malformed(line) => SmtpError::Protocol {
            stage: stage.as_str(),
            message: format!("unparseable reply line {line:?}"),
        },
    })
}

fn is_final_line(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes.len() >= 3
        && bytes[..3].iter().all(u8::is_ascii_digit)
        && (bytes.len() == 3 || bytes[3] == b' ')
}

async fn ehlo_exchange_on(reader: &mut BufReader<Stream>, cfg: &ConnectConfig, conn_id: u64) -> Result<Vec<String>, SmtpError> {
    let mut reply = ehlo_or_helo(reader, cfg, "EHLO", conn_id).await?;
    if reply.code != 250 {
        reply = ehlo_or_helo(reader, cfg, "HELO", conn_id).await?;
        if reply.code != 250 {
            return Err(SmtpError::Rejected {
                stage: Stage::Ehlo.as_str(),
                code: reply.code,
                text: reply.summary(),
            });
        }
        // HELO has no capability list.
        return Ok(Vec::new());
    }
    Ok(reply
        .lines
        .iter()
        .skip(1)
        .filter_map(|line| line.get(4..))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter(|keyword| !keyword.is_empty())
        .map(|keyword| keyword.to_ascii_uppercase())
        .collect())
}

async fn ehlo_or_helo(reader: &mut BufReader<Stream>, cfg: &ConnectConfig, verb: &str, conn_id: u64) -> Result<SmtpReply, SmtpError> {
    send_line(
        reader.get_mut(),
        &format!("{verb} {}", cfg.ehlo_name),
        Stage::Ehlo,
        cfg.timeout,
        conn_id,
    )
    .await?;
    read_reply_from(reader, Stage::Ehlo, cfg.timeout, conn_id).await
}

fn map_io_error(e: std::io::Error, stage: Stage) -> SmtpError {
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::BrokenPipe => SmtpError::Closed {
            stage: stage.as_str(),
        },
        _ => SmtpError::Io {
            stage: stage.as_str(),
            source: e,
        },
    }
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

async fn tls_upgrade(tcp: TcpStream, cfg: &ConnectConfig, conn_id: u64) -> Result<(TlsStream<TcpStream>, TlsSummary), SmtpError> {
    let connector = TlsConnector::from(tls_client_config(cfg.insecure));
    let server_name = ServerName::try_from(cfg.host.clone())
        .map_err(|e| SmtpError::Tls(format!("invalid server name {host:?}: {e}", host = cfg.host)))?;
    match tokio::time::timeout(cfg.timeout, connector.connect(server_name, tcp)).await {
        Ok(Ok(stream)) => {
            let version = stream
                .get_ref()
                .1
                .protocol_version()
                .map(|v| format!("{v:?}").replace('_', "."))
                .unwrap_or_else(|| "unknown".to_string());
            let summary = TlsSummary {
                version: version.clone(),
                host: cfg.host.clone(),
                verified: !cfg.insecure,
            };
            tracing::debug!(
                target: TRANSCRIPT_TARGET,
                conn = conn_id,
                "<<< [TLS {version} established for {}; certificate verified: {}]",
                cfg.host,
                summary.verified
            );
            Ok((stream, summary))
        }
        Ok(Err(e)) => Err(SmtpError::Tls(e.to_string())),
        Err(_) => Err(SmtpError::Timeout {
            stage: Stage::TlsHandshake.as_str(),
            secs: cfg.timeout.as_secs().max(1),
        }),
    }
}

fn tls_client_config(insecure: bool) -> Arc<ClientConfig> {
    static VERIFYING: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    static INSECURE: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();

    if insecure {
        INSECURE.get_or_init(|| Arc::new(build_client_config(true))).clone()
    } else {
        VERIFYING.get_or_init(|| Arc::new(build_client_config(false))).clone()
    }
}

fn build_client_config(insecure: bool) -> ClientConfig {
    // Pure-Rust provider (RustCrypto): no ring/aws-lc-rs C build required.
    let provider: Arc<rustls::crypto::CryptoProvider> = Arc::new(rustls_rustcrypto::provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls provider supports safe default protocol versions");
    if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth()
    } else {
        let roots = RootCertStore {
            roots: TLS_SERVER_ROOTS.to_vec(),
        };
        builder.with_root_certificates(roots).with_no_client_auth()
    }
}

/// A [`ServerCertVerifier`] that accepts any certificate. Only reachable when
/// the user explicitly passes `--insecure` for legacy mail servers with
/// self-signed or expired certificates.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

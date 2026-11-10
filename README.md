<div align="center">

# rcptx

**Smart, asynchronous SMTP reconnaissance & deliverability probing — without sending a single email.**

[![CI](https://github.com/sametcn99/rcptx/actions/workflows/ci.yml/badge.svg)](https://github.com/sametcn99/rcptx/actions/workflows/ci.yml)
[![Release](https://github.com/sametcn99/rcptx/actions/workflows/release.yml/badge.svg)](https://github.com/sametcn99/rcptx/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/sametcn99/rcptx?color=blue)](https://github.com/sametcn99/rcptx/releases/latest)
[![Made with Rust](https://img.shields.io/badge/made%20with-Rust-orange)](https://www.rust-lang.org/)

[Website](https://sametcn99.github.io/rcptx/) · [Releases](https://github.com/sametcn99/rcptx/releases) · [Issues](https://github.com/sametcn99/rcptx/issues) · [Usage guide](#usage-guide)

</div>

---

`rcptx` probes recipient validity, MX posture and catch-all behaviour
using the SMTP protocol itself (`EHLO` → `STARTTLS` → `MAIL FROM` →
`RCPT TO` → `RSET`). It classifies each candidate from the 3-digit reply code
**and** RFC 3463 enhanced status codes, reuses sessions intelligently, and
plays nice with greylisting, tarpits and anti-enumeration defences.

```text
$ rcptx -d acme.com

 acme.com
──────────────────────────────────────────────────────────────────
  MX        10 aspmx.l.google.com  |  20 alt1.aspmx.l.google.com
  Provider  Google Workspace
  SPF       v=spf1 include:_spf.google.com ~all
  DMARC     v=DMARC1; p=quarantine
  Catch-All no
┌────────────────────┬──────────┬──────┬───────┬─────┬─────┬──────────────┐
│ Email              ┆ Status   ┆ Code ┆ ESC   ┆ Try ┆ ms  ┆ Message      ┆
╞════════════════════╪══════════╪══════╪═══════╪═════╪═════╪══════════════╡
│ careers@acme.com   ┆ accepted ┆ 250  ┆ 2.1.5 ┆ 1   ┆ 143 ┆ 2.1.5 OK     ┆
│ hr@acme.com        ┆ accepted ┆ 250  ┆ 2.1.5 ┆ 1   ┆ 121 ┆ 2.1.5 OK     ┆
│ nobody@acme.com    ┆ rejected ┆ 550  ┆ 5.1.1 ┆ 1   ┆ 118 ┆ User unknown ┆
└────────────────────┴──────────┴──────┴───────┴─────┴─────┴──────────────┘
Summary: 22 probe(s) across 1 domain(s) — 3 accepted · 0 catch-all* · 19 rejected …
```

## Contents

- [Features](#features)
- [Installation](#installation)
- [Usage guide](#usage-guide)
- [Verdicts](#output-verdicts)
- [Smart behaviour](#smart-behaviour)
- [Update checks](#update-checks)
- [Exit codes](#exit-codes)
- [Continuous integration & releases](#continuous-integration--releases)
- [Contributing](#contributing)
- [Legal & ethical use](#legal--ethical-use)
- [License](#license)

## Features

- **Async end-to-end** (tokio): concurrent per-domain probing with bounded
  connection counts, timeouts on every operation and graceful `Ctrl+C`
  shutdown (press twice to abort hard; partial results are always printed).
- **Session reuse (`RSET` multiplexing)** — one connection probes a batch of
  candidates (`MAIL FROM` → `RCPT TO` → `RSET` per candidate, controlled by
  `--max-rcpt-per-conn`) instead of a fresh TCP+TLS handshake per address.
  If a server drops the session mid-batch (421 / reset / timeout), the probe
  transparently reconnects and **resumes from the failed candidate**, failing
  over to lower-priority MX hosts when needed.
- **Accurate verdicts** from the 3-digit code _and_ enhanced status codes
  (RFC 3463): `accepted`, `accepted_catch_all`, `rejected`, `temporary`,
  `policy_blocked`, `indeterminate` (`252`), `error`.
- **Catch-all detection** via random UUID local-parts before candidate
  scanning; `--stop-on-catch-all` skips hopeless scans.
- **DNS & security recon**: MX (sorted, null-MX aware), SPF, DMARC and a
  provider guess (Google Workspace, Microsoft 365, Proofpoint, Mimecast,
  Barracuda, Cloudflare, iCloud, …). Custom resolver via `--dns-server`.
- **Greylisting support**: `4xx` replies are retried (`--retry-greylist`,
  `--retry-delay`).
- **Anti-blocking posture**: `--delay-ms` + `--jitter-ms` jittered pacing,
  `--concurrency` limiter, `--random-ehlo`, `--auto-mail-from` plausible
  sender generation.
- **TLS everywhere**: opportunistic / required / disabled STARTTLS, implicit
  TLS on port 465, `--insecure` for legacy self-signed servers. Built on a
  **pure-Rust crypto provider** — the binary compiles without any C toolchain.
- **Four output formats**: human `table`, `json` document, streaming `jsonl`
  and `csv`; `--only-accepted` filter; `--output <FILE>`; progress bars that
  auto-hide when piping or when writing machine formats.
- **Update checks** straight from GitHub Releases: `rcptx check-update`
  or `--check-update` (see [Update checks](#update-checks)).
- **77 automated tests**, including an in-process scripted SMTP server that
  exercises session reuse, reconnect-resume, catch-all logic and greylist
  retries end-to-end.

## Installation

### Prebuilt binaries

Download from the [latest release](https://github.com/sametcn99/rcptx/releases/latest):

| Platform              | File                                         |
| --------------------- | -------------------------------------------- |
| Linux (x86_64)        | `rcptx-x86_64-unknown-linux-gnu.tar.gz` |
| macOS (Apple Silicon) | `rcptx-aarch64-apple-darwin.tar.gz`     |
| macOS (Intel)         | `rcptx-x86_64-apple-darwin.tar.gz`      |
| Windows (x64)         | `rcptx-x86_64-pc-windows-msvc.zip`      |

Each archive carries a matching `.sha256` checksum.

### From source

```sh
# Install directly from GitHub
cargo install --git https://github.com/sametcn99/rcptx

# Or build from a checkout
git clone https://github.com/sametcn99/rcptx
cd rcptx
cargo build --release
```

## Usage guide

```sh
# 1. Probe a domain with the default presets (hr, general), live progress
rcptx -d example.com

# 2. HR + executive hunt on several domains from a file, JSON report, keep only hits
rcptx -D targets.txt -p hr,executive --only-accepted --format json -o hits.json

# 3. Stream accepted addresses as CSV while probing, custom sender + resolver
cat domains.txt | rcptx --stdin -l careers,people,ceo \
    --auto-mail-from --dns-server 1.1.1.1 --format csv

# 4. Slow, cautious scan of a well-defended domain (no catch-all waste, greylist retries)
rcptx -d strict-corp.com -p all -c 1 --delay-ms 2000 --jitter-ms 800 \
    --max-rcpt-per-conn 3 --stop-on-catch-all --retry-greylist 2 --retry-delay 30

# 5. DNS-only posture check (no SMTP traffic at all)
rcptx mx example.com --format json

# 6. Debugging: -v prints the raw SMTP transcript (>>> MAIL FROM, <<< 250 ...)
rcptx -d example.com -l info --catch-all-probes 1 -v
```

### Key flags

| Flag                                                    | Default                | Purpose                                                                                   |
| ------------------------------------------------------- | ---------------------- | ----------------------------------------------------------------------------------------- |
| `-d, --domain` / `-D, --domains-file` / `--stdin`       | —                      | Targets (domains or full addresses)                                                       |
| `-p, --preset`                                          | `hr,general`           | Built-in local-part dictionaries (`hr`, `general`, `support`, `tech`, `executive`, `all`) |
| `-w, --wordlist` / `-l, --local-parts` / `--no-presets` | —                      | Custom / inline candidates                                                                |
| `-f, --mail-from` / `--auto-mail-from[=DOMAIN]`         | `probe@example.com`    | Envelope sender                                                                           |
| `--port`                                                | `25`                   | SMTP port (25, 587 submission, 465 implicit TLS)                                          |
| `--mx-host` / `--no-mx-failover`                        | —                      | Direct server override / disable MX failover                                              |
| `--starttls`                                            | `opportunistic`        | `opportunistic` · `required` · `disabled`                                                 |
| `--insecure`                                            | off                    | Skip TLS certificate verification                                                         |
| `--dns-server`                                          | system                 | Custom resolver (e.g. `1.1.1.1`, `8.8.8.8`)                                               |
| `-c, --concurrency`                                     | `2`                    | Concurrent SMTP connections per domain                                                    |
| `--max-rcpt-per-conn`                                   | `5`                    | RCPT probes per session before reconnecting                                               |
| `--delay-ms` / `--jitter-ms`                            | `300` / `150`          | Jittered pacing between probes                                                            |
| `--catch-all-probes` / `--stop-on-catch-all`            | `2` / off              | Catch-all detection                                                                       |
| `--retry-greylist` / `--retry-delay`                    | `1` / `15s`            | Greylist retries                                                                          |
| `--format` / `-o, --output` / `--only-accepted`         | `table` / stdout / off | Output control                                                                            |
| `-q, --quiet` / `-v, --verbose`                         | off / 0                | Noise control; `-v` shows the SMTP transcript                                             |

Run `rcptx --help` for the full reference.

## Output verdicts

| Verdict              | Meaning                                                            |
| -------------------- | ------------------------------------------------------------------ |
| `accepted`           | `250`/`251` — mailbox exists and accepts mail                      |
| `accepted_catch_all` | accepted, but the domain accepts _every_ address                   |
| `rejected`           | `550 5.1.1`-style — user unknown / mailbox unavailable             |
| `temporary`          | `4xx` — greylisted, rate-limited, try later                        |
| `policy_blocked`     | `5.7.x` / `554` / sender-stage rejection — anti-enumeration policy |
| `indeterminate`      | `252` — cannot VRFY, but will accept                               |
| `error`              | connection timeout, TLS failure, unreachable MX                    |

## Smart behaviour

- **Session reuse**: with the defaults (2 concurrent connections, 5 RCPTs per
  session) a 22-candidate scan costs ~5 handshakes instead of 22.
- **MX failover** (on by default): _connect_ failures, not SMTP replies,
  trigger failover — a `550` from the primary MX is a real answer, not a
  reason to move on.
- **Policy detection**: a rejection at `MAIL FROM` (before any recipient is
  named) is classified `policy_blocked`, as are `5.7.x` enhanced codes and
  blocklist-flavoured text — these say nothing about the candidate itself.
- **Null MX** (RFC 7505) and MX-less domains are handled: the latter falls
  back to the implicit MX (the domain's A record) per RFC 5321 §5.1.

## Update checks

`rcptx` can compare its version against the
[GitHub releases](https://github.com/sametcn99/rcptx/releases) of this repository:

```sh
# Standalone check
rcptx check-update

# Or before any run (non-fatal — a flaky network never stops a scan)
rcptx -d example.com --check-update
```

## Exit codes

| Code | Meaning                                                                  |
| ---- | ------------------------------------------------------------------------ |
| `0`  | Completed (also for Ctrl+C partial runs)                                 |
| `1`  | Configuration or runtime error                                           |
| `2`  | All TCP connection attempts timed out — outbound port 25 appears blocked |

## Continuous integration & releases

- **[CI](https://github.com/sametcn99/rcptx/actions/workflows/ci.yml)** runs
  `cargo fmt --check`, `cargo clippy -D warnings` and the full test suite on
  Ubuntu, Windows and macOS for every push and pull request.
- **[Release](https://github.com/sametcn99/rcptx/actions/workflows/release.yml)**
  builds signed-checksummed archives for Linux, macOS (Apple Silicon + Intel)
  and Windows whenever a `v*` tag is pushed, and publishes them to
  [Releases](https://github.com/sametcn99/rcptx/releases).

## Contributing

Issues and pull requests are welcome at <https://github.com/sametcn99/rcptx>.
Please make sure `cargo fmt --check`, `cargo clippy --all-targets -- -D
warnings` and `cargo test` all pass locally — CI enforces the same.

## Legal & ethical use

Probe only domains you have a legitimate reason to investigate (your own
infrastructure, authorized assessments, deliverability research). Recipient
enumeration may be restricted by law or terms of service in your
jurisdiction. Be gentle: the rate-limit defaults exist to keep you polite.

---

<p align="center">🌐 Project website: <a href="https://sametcn99.github.io/rcptx/">sametcn99.github.io/rcptx</a></p>

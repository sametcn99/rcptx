# smtp-probe

Smart, asynchronous SMTP reconnaissance & deliverability CLI written in Rust.
Probes recipient validity, MX posture and catch-all behaviour — **without
sending a single email** — using the SMTP protocol itself (`EHLO` →
`STARTTLS` → `MAIL FROM` → `RCPT TO` → `RSET`).

```
$ smtp-probe -d acme.com

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
```

## Features

- **Async end-to-end** (tokio): concurrent per-domain probing with bounded
  connection counts, timeouts on every operation and graceful `Ctrl+C`
  shutdown (press twice to abort hard; partial results are always printed).
- **Session reuse (`RSET` multiplexing)** — one connection probes a batch of
  candidates (`MAIL FROM` → `RCPT TO` → `RSET` per candidate, `--max-rcpt-per-conn`
  per session) instead of a fresh TCP+TLS handshake per address. If the server
  drops the session mid-batch (421 / reset / timeout), the probe transparently
  reconnects and **resumes from the failed candidate**, failing over to
  lower-priority MX hosts when needed.
- **Accurate verdicts** from the 3-digit code *and* RFC 3463 enhanced status
  codes: `accepted`, `accepted_catch_all`, `rejected`, `temporary`,
  `policy_blocked`, `indeterminate` (252), `error`.
- **Catch-all detection** via random UUID local-parts before candidate
  scanning; `--stop-on-catch-all` skips hopeless scans.
- **DNS & security recon**: MX (sorted, null-MX aware), SPF, DMARC and a
  provider guess (Google Workspace, Microsoft 365, Proofpoint, Mimecast, …).
  Custom resolver via `--dns-server`.
- **Greylisting support**: 4xx replies are retried (`--retry-greylist`,
  `--retry-delay`).
- **Anti-blocking posture**: `--delay-ms` + `--jitter-ms` jittered pacing,
  `--concurrency` limiter, `--random-ehlo`, `--auto-mail-from` plausible
  sender generation.
- **TLS everywhere**: opportunistic/required/disabled STARTTLS, implicit TLS
  on port 465, `--insecure` for legacy self-signed servers. Pure-Rust crypto
  provider — no C toolchain needed to build.
- **Four output formats**: human `table`, `json` document, streaming `jsonl`
  and `csv`; `--only-accepted` filter; `--output <FILE>`; progress bars that
  auto-hide when piping or writing machine formats.
- **Exit codes**: `0` ok · `1` configuration/runtime error · `2` outbound
  port appears blocked (every TCP connect timed out).

## Install

```sh
cargo install --path .   # from a checkout
cargo build --release    # or just build locally
```

## Usage examples

```sh
# 1. Probe a domain with the default presets (hr, general), live progress
smtp-probe -d example.com

# 2. HR + executive hunt on several domains from a file, JSON report, keep only hits
smtp-probe -D targets.txt -p hr,executive --only-accepted --format json -o hits.json

# 3. Stream accepted addresses as CSV while probing, custom sender + resolver
cat domains.txt | smtp-probe --stdin -l careers,people,ceo \
    --auto-mail-from --dns-server 1.1.1.1 --format csv

# 4. Slow, cautious scan of a well-defended domain (no catch-all waste, greylist retries)
smtp-probe -d strict-corp.com -p all -c 1 --delay-ms 2000 --jitter-ms 800 \
    --max-rcpt-per-conn 3 --stop-on-catch-all --retry-greylist 2 --retry-delay 30

# 5. DNS-only posture check (no SMTP traffic at all)
smtp-probe mx example.com --format json

# Debugging: -v prints the raw SMTP transcript (>>> MAIL FROM, <<< 250 ...)
smtp-probe -d example.com -l info --catch-all-probes 1 -v
```

## Smart behaviour notes

- **Session reuse**: with the defaults (2 concurrent connections, 5 RCPTs per
  session) a 22-candidate scan costs ~5 handshakes instead of 22.
- **MX failover** (`--mx-failover`, on by default, `--no-mx-failover` to
  disable): connect failures, not SMTP replies, trigger failover — a `550`
  from the primary is a real answer, not a reason to move on.
- **Policy detection**: a rejection at `MAIL FROM` (before any recipient is
  named) is classified `policy_blocked`, as are `5.7.x` enhanced codes and
  blocklist-flavoured text — these say nothing about the candidate.
- **Null MX** (RFC 7505) and MX-less domains are handled: the latter falls
  back to the implicit MX (the domain's A record) per RFC 5321 §5.1.

## Output verdicts

| Verdict | Meaning |
| --- | --- |
| `accepted` | `250`/`251` — mailbox exists and accepts mail |
| `accepted_catch_all` | accepted, but the domain accepts *every* address |
| `rejected` | `550 5.1.1`-style — user unknown / mailbox unavailable |
| `temporary` | `4xx` — greylisted, rate-limited, try later |
| `policy_blocked` | `5.7.x` / `554` / sender-stage rejection — anti-enumeration policy |
| `indeterminate` | `252` — cannot VRFY, but will accept |
| `error` | connection timeout, TLS failure, unreachable MX |

## Legal & ethical use

Probe only domains you have a legitimate reason to investigate (your own
infrastructure, authorized assessments, deliverability research). Recipient
enumeration may be restricted by law or terms of service in your
jurisdiction. Be gentle: the rate-limit defaults exist to keep you polite.

## License

MIT OR Apache-2.0

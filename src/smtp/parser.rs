//! Multi-line SMTP reply parsing and RFC 3463 enhanced status code extraction.
//!
//! An SMTP reply is one or more lines of the form
//!
//! ```text
//! 250-PIPELINING
//! 250-SIZE 157286400
//! 250 SMTPUTF8
//! ```
//!
//! The final line uses a space separator; continuation lines use `-`.
//! Replies may additionally carry an enhanced status code such as `5.1.1`
//! anywhere in the text (RFC 3463), which this module extracts for accurate
//! verdict classification.

use std::fmt;

use thiserror::Error;

/// Failures produced while decoding an SMTP reply.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// The peer closed the connection before a complete reply arrived.
    #[error("connection closed before a complete reply arrived")]
    Incomplete,
    /// A reply line did not follow the `DDD<sep>text` grammar.
    #[error("malformed SMTP reply line: {0:?}")]
    Malformed(String),
}

/// An RFC 3463 enhanced status code (`class.subject.detail`, e.g. `5.1.1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnhancedCode {
    /// 2 (success), 4 (persistent transient) or 5 (permanent failure).
    pub class: u8,
    /// Subject code, e.g. 1 (addressing).
    pub subject: u8,
    /// Detail code, e.g. 1 (bad destination mailbox).
    pub detail: u8,
}

impl fmt::Display for EnhancedCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.class, self.subject, self.detail)
    }
}

/// A fully parsed (possibly multi-line) SMTP reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpReply {
    /// The 3-digit reply code from the final line.
    pub code: u16,
    /// Raw reply lines, including the `250-` / `250 ` prefixes.
    pub lines: Vec<String>,
    /// All text after the code prefixes, joined with a single space.
    pub text: String,
    /// The first enhanced status code found in the text, if any.
    pub enhanced: Option<EnhancedCode>,
}

impl SmtpReply {
    /// A short, single-line summary of the reply suitable for reports.
    pub fn summary(&self) -> String {
        let collapsed: String = self.text.split_whitespace().collect::<Vec<_>>().join(" ");
        if collapsed.is_empty() {
            return format!("SMTP {}", self.code);
        }
        if collapsed.chars().count() > 200 {
            let truncated: String = collapsed.chars().take(200).collect();
            return format!("{truncated}…");
        }
        collapsed
    }
}

/// Extract the first RFC 3463 enhanced status code from free-form text.
///
/// Punctuation around tokens (e.g. `(5.1.1)` or `5.7.1;`) is ignored. IPv4
/// addresses and version markers such as `v=DMARC1` never match because the
/// class must be a single digit in the set {2, 4, 5}.
pub fn parse_enhanced(text: &str) -> Option<EnhancedCode> {
    for token in text.split_whitespace() {
        let trimmed = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.');
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() != 3 || parts[0].len() != 1 {
            continue;
        }
        if let (Ok(class), Ok(subject), Ok(detail)) = (
            parts[0].parse::<u8>(),
            parts[1].parse::<u8>(),
            parts[2].parse::<u8>(),
        ) && matches!(class, 2 | 4 | 5)
        {
            return Some(EnhancedCode {
                class,
                subject,
                detail,
            });
        }
    }
    None
}
/// Parse a complete set of raw reply lines into an [`SmtpReply`].
///
/// Lines are the already-read `250-PIPELINING` style strings with CRLF
/// stripped. Continuation lines must use the `-` separator and every line but
/// the last must be a continuation.
///
/// # Errors
///
/// Returns [`ParseError::Incomplete`] for an empty slice and
/// [`ParseError::Malformed`] for lines that violate the reply grammar.
pub fn parse_reply(raw: &[String]) -> Result<SmtpReply, ParseError> {
    if raw.is_empty() {
        return Err(ParseError::Incomplete);
    }

    let mut code: u16 = 0;
    let mut texts: Vec<String> = Vec::with_capacity(raw.len());
    let last = raw.len() - 1;

    for (i, line) in raw.iter().enumerate() {
        let bytes = line.as_bytes();
        if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
            return Err(ParseError::Malformed(line.clone()));
        }
        let line_code: u16 = line[..3]
            .parse()
            .map_err(|_| ParseError::Malformed(line.clone()))?;
        if !(200..=599).contains(&line_code) {
            return Err(ParseError::Malformed(line.clone()));
        }

        let separator = line.chars().nth(3);
        let is_last = i == last;
        match separator {
            // A bare "250" final line.
            None if is_last => {}
            Some('-') if !is_last => {}
            Some(' ') if is_last => {}
            _ => return Err(ParseError::Malformed(line.clone())),
        }

        if is_last {
            code = line_code;
        }
        texts.push(if line.len() > 4 {
            line[4..].to_string()
        } else {
            String::new()
        });
    }

    let text = texts.join(" ");
    let enhanced = parse_enhanced(&text);
    Ok(SmtpReply {
        code,
        lines: raw.to_vec(),
        text,
        enhanced,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_simple_reply() {
        let reply = parse_reply(&lines(&["250 OK"])).unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(reply.text, "OK");
        assert!(reply.enhanced.is_none());
    }

    #[test]
    fn parses_multiline_ehlo_reply() {
        let raw = lines(&[
            "250-mail.example.com greets you",
            "250-PIPELINING",
            "250-SIZE 10485760",
            "250 STARTTLS",
        ]);
        let reply = parse_reply(&raw).unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(reply.lines.len(), 4);
        assert!(reply.text.contains("PIPELINING"));
        assert!(reply.text.contains("STARTTLS"));
    }

    #[test]
    fn parses_enhanced_status_codes() {
        let reply = parse_reply(&lines(&[
            "550 5.1.1 <nope@example.com>: Recipient address rejected: User unknown",
        ]))
        .unwrap();
        assert_eq!(reply.code, 550);
        let esc = reply.enhanced.unwrap();
        assert_eq!(esc.to_string(), "5.1.1");

        let greylisted = parse_reply(&lines(&["450 4.7.1 Greylisted, try again later"])).unwrap();
        assert_eq!(greylisted.enhanced.unwrap().to_string(), "4.7.1");
    }

    #[test]
    fn enhanced_extraction_ignores_ips_and_versions() {
        assert!(parse_enhanced("connection from 192.168.1.1 blocked").is_none());
        assert!(parse_enhanced("v=DMARC1; p=reject").is_none());
        assert_eq!(
            parse_enhanced("(5.7.1) policy violation")
                .unwrap()
                .to_string(),
            "5.7.1"
        );
        assert_eq!(
            parse_enhanced("recipient 2.1.5; queued")
                .unwrap()
                .to_string(),
            "2.1.5"
        );
        assert!(parse_enhanced("code 45.1.1").is_none());
    }

    #[test]
    fn rejects_malformed_lines() {
        assert_eq!(
            parse_reply(&lines(&["hello world"])),
            Err(ParseError::Malformed("hello world".into()))
        );
        // Missing final line: middle line uses '-' but is last.
        assert_eq!(
            parse_reply(&lines(&["250-PIPELINING"])),
            Err(ParseError::Malformed("250-PIPELINING".into()))
        );
    }

    #[test]
    fn incomplete_when_no_lines() {
        assert_eq!(parse_reply(&[]), Err(ParseError::Incomplete));
    }

    #[test]
    fn final_line_code_wins_over_mismatched_continuations() {
        // Some real servers are sloppy; the final line is authoritative.
        let reply = parse_reply(&lines(&["550-odd mismatch", "250 Ok"])).unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(reply.text, "odd mismatch Ok");
    }

    #[test]
    fn out_of_range_codes_are_rejected() {
        assert!(parse_reply(&lines(&["199 too low"])).is_err());
        assert!(parse_reply(&lines(&["600 too high"])).is_err());
        assert!(parse_reply(&lines(&["2x0 not numeric"])).is_err());
    }

    #[test]
    fn ehlo_shaped_replies_parse_cleanly() {
        let reply = parse_reply(&lines(&[
            "250-mail.example.com",
            "250-PIPELINING",
            "250-SIZE 20480000",
            "250-STARTTLS",
            "250 ENHANCEDSTATUSCODES",
        ]))
        .unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(reply.lines.len(), 5);
        assert!(reply.text.contains("STARTTLS"));
        assert!(reply.text.contains("mail.example.com"));
    }

    #[test]
    fn summary_collapses_and_truncates() {
        let reply = parse_reply(&lines(&[
            "250-mail.example.com",
            "250 very   long    spacing",
        ]))
        .unwrap();
        assert_eq!(reply.summary(), "mail.example.com very long spacing");

        let long = "x".repeat(300);
        let reply = parse_reply(&lines(&[&format!("250 {long}")])).unwrap();
        assert!(reply.summary().chars().count() <= 202);
        assert!(reply.summary().ends_with('…'));
    }
}

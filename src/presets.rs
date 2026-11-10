//! Built-in local-part dictionaries categorized by profile.
//!
//! Presets are selected with `-p/--preset` as a comma-separated list
//! (`hr,general`). The special preset `all` combines every category.

use anyhow::{anyhow, Result};

/// Recruiting / people-operations mailboxes.
pub const HR: &[&str] = &[
    "careers",
    "career",
    "jobs",
    "job",
    "hr",
    "humanresources",
    "recruitment",
    "recruiting",
    "talent",
    "talentacquisition",
    "people",
    "peopleops",
    "work",
    "join",
    "joinus",
];

/// General-purpose public mailboxes.
pub const GENERAL: &[&str] = &["info", "contact", "hello", "office", "mail", "press", "media"];

/// Customer support and service desks.
pub const SUPPORT: &[&str] = &["support", "help", "helpdesk", "service", "billing", "sales"];

/// Technical / administrative role accounts (RFC 2142 flavored).
pub const TECH: &[&str] = &["admin", "security", "webmaster", "postmaster", "hostmaster", "devops", "it"];

/// Executive / leadership aliases.
pub const EXECUTIVE: &[&str] = &[
    "ceo",
    "cfo",
    "coo",
    "cto",
    "cio",
    "founder",
    "president",
    "board",
    "chairman",
    "ir",
    "investors",
];

/// Every valid preset name accepted by `-p/--preset`.
pub const PRESET_NAMES: &[&str] = &["hr", "general", "support", "tech", "executive", "all"];

/// Default preset specification used when `-p` is omitted.
pub const DEFAULT_SPEC: &str = "hr,general";

fn lookup(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "hr" => Some(HR),
        "general" => Some(GENERAL),
        "support" => Some(SUPPORT),
        "tech" => Some(TECH),
        "executive" => Some(EXECUTIVE),
        _ => None,
    }
}

fn push_all(out: &mut Vec<String>, words: &'static [&'static str]) {
    for word in words {
        let w = word.to_lowercase();
        if !out.contains(&w) {
            out.push(w);
        }
    }
}

/// Resolve a comma-separated preset specification into a de-duplicated,
/// order-preserving list of local-parts.
///
/// # Errors
///
/// Returns an error naming the offending token when an unknown preset is
/// requested.
pub fn resolve(spec: &str) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for token in spec.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let name = token.to_lowercase();
        if name == "all" {
            for group in [HR, GENERAL, SUPPORT, TECH, EXECUTIVE] {
                push_all(&mut out, group);
            }
        } else {
            let group = lookup(&name).ok_or_else(|| {
                anyhow!("unknown preset '{token}' (valid presets: {})", PRESET_NAMES.join(", "))
            })?;
            push_all(&mut out, group);
        }
    }
    if out.is_empty() {
        return Err(anyhow!("preset specification '{spec}' produced no local-parts"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_single_preset() {
        let parts = resolve("support").unwrap();
        assert_eq!(parts, SUPPORT.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    }

    #[test]
    fn merges_and_dedupes_multiple_presets() {
        let parts = resolve("hr,general,hr").unwrap();
        assert_eq!(parts.len(), HR.len() + GENERAL.len());
        // "mail" only exists in general; "hr" only in hr — no duplicates overall.
        let mut sorted = parts.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), parts.len());
    }

    #[test]
    fn all_combines_every_preset() {
        let parts = resolve("all").unwrap();
        assert!(parts.len() > HR.len() + GENERAL.len());
        for expected in ["ceo", "postmaster", "helpdesk", "joinus", "press"] {
            assert!(parts.iter().any(|p| p == expected), "missing {expected}");
        }
    }

    #[test]
    fn rejects_unknown_preset() {
        assert!(resolve("nope").is_err());
    }

    #[test]
    fn empty_spec_is_rejected() {
        assert!(resolve(" , ").is_err());
    }
}

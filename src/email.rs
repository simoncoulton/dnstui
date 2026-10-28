//! Parsing and linting of the e-mail authentication records (SPF, DMARC,
//! DKIM). Pure functions over record text, so they are easy to test; the
//! engine does the DNS lookups they need.

use std::collections::BTreeMap;

use crate::report::Finding;

/// The DNS-lookup budget RFC 7208 gives an SPF evaluation.
pub const SPF_LOOKUP_LIMIT: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfTerm {
    /// `+`, `-`, `~` or `?`; `+` when omitted. Always `+` for modifiers.
    pub qualifier: char,
    /// `include`, `a`, `mx`, `all`, `redirect`, ...
    pub name: String,
    /// Everything after `:` or `=`, or a bare `/cidr` suffix.
    pub value: Option<String>,
    pub modifier: bool,
}

impl SpfTerm {
    /// The domain this term makes the evaluator look up, if it names one.
    pub fn include_target(&self) -> Option<&str> {
        match (self.name.as_str(), &self.value) {
            ("include" | "redirect", Some(v)) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Whether evaluating this term costs a DNS lookup.
    pub fn costs_lookup(&self) -> bool {
        matches!(
            self.name.as_str(),
            "include" | "a" | "mx" | "ptr" | "exists" | "redirect"
        )
    }
}

/// True for a TXT string that is an SPF record (`v=spf1` then space or end).
pub fn is_spf(txt: &str) -> bool {
    let t = txt.trim();
    t.len() >= 6
        && t[..6].eq_ignore_ascii_case("v=spf1")
        && t[6..].chars().next().is_none_or(char::is_whitespace)
}

pub fn parse_spf(record: &str) -> Result<Vec<SpfTerm>, String> {
    if !is_spf(record) {
        return Err("does not start with v=spf1".into());
    }
    let mut terms = Vec::new();
    for raw in record.split_whitespace().skip(1) {
        // `name=value` is a modifier; mechanisms use `:` or `/` instead.
        if let Some((name, value)) = raw.split_once('=')
            && !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            && !raw.contains(':')
        {
            terms.push(SpfTerm {
                qualifier: '+',
                name: name.to_ascii_lowercase(),
                value: Some(value.to_string()),
                modifier: true,
            });
            continue;
        }
        let (qualifier, body) = match raw.chars().next() {
            Some(q @ ('+' | '-' | '~' | '?')) => (q, &raw[1..]),
            _ => ('+', raw),
        };
        let split = body.find([':', '/']).unwrap_or(body.len());
        let (name, rest) = body.split_at(split);
        let name = name.to_ascii_lowercase();
        if !matches!(
            name.as_str(),
            "all" | "include" | "a" | "mx" | "ptr" | "ip4" | "ip6" | "exists"
        ) {
            return Err(format!("unknown mechanism '{raw}'"));
        }
        let value = match rest {
            "" => None,
            r => Some(r.strip_prefix(':').unwrap_or(r).to_string()),
        };
        if matches!(name.as_str(), "include" | "exists" | "ip4" | "ip6") && value.is_none() {
            return Err(format!("'{name}' needs a value"));
        }
        terms.push(SpfTerm {
            qualifier,
            name,
            value,
            modifier: false,
        });
    }
    Ok(terms)
}

/// Findings for the TXT strings found at a domain. `lookups` is the total DNS
/// lookup count including nested includes, when the engine could work it out.
pub fn lint_spf(txts: &[String], lookups: Option<usize>) -> Vec<Finding> {
    let records: Vec<&String> = txts.iter().filter(|t| is_spf(t)).collect();
    let mut out = Vec::new();
    match records.len() {
        0 => {
            out.push(Finding::fail(
                "SPF record",
                "No SPF record found. Receivers can't tell which servers may send for this domain.",
            ));
            return out;
        }
        1 => out.push(Finding::ok(
            "SPF record",
            "Exactly one SPF record published.",
        )),
        n => out.push(Finding::fail(
            "SPF record",
            format!("{n} SPF records found; a domain must publish exactly one (RFC 7208 §4.5)."),
        )),
    }
    let terms = match parse_spf(records[0]) {
        Ok(t) => {
            out.push(Finding::ok("SPF syntax", "The record parses."));
            t
        }
        Err(e) => {
            out.push(Finding::fail("SPF syntax", e));
            return out;
        }
    };

    let all = terms.iter().find(|t| !t.modifier && t.name == "all");
    let redirect = terms.iter().any(|t| t.modifier && t.name == "redirect");
    match all.map(|t| t.qualifier) {
        Some('-') => out.push(Finding::ok("SPF policy", "-all: mail from other servers fails.")),
        Some('~') => out.push(Finding::ok(
            "SPF policy",
            "~all: mail from other servers is soft-failed. Fine while rolling out; -all is stricter.",
        )),
        Some('?') => out.push(Finding::warn(
            "SPF policy",
            "?all is neutral: the record doesn't restrict anything.",
        )),
        Some(_) => out.push(Finding::fail(
            "SPF policy",
            "+all authorises every server on the internet to send as this domain.",
        )),
        None if redirect => out.push(Finding::info("SPF policy", "Delegated by redirect=.")),
        None => out.push(Finding::warn(
            "SPF policy",
            "No 'all' mechanism, so the result for unlisted senders is neutral.",
        )),
    }
    if terms.iter().any(|t| !t.modifier && t.name == "ptr") {
        out.push(Finding::warn(
            "SPF ptr",
            "The 'ptr' mechanism is slow and discouraged by RFC 7208; remove it.",
        ));
    }
    if let Some(pos) = terms.iter().position(|t| !t.modifier && t.name == "all")
        && pos + 1 < terms.iter().filter(|t| !t.modifier).count()
    {
        out.push(Finding::warn(
            "SPF order",
            "Mechanisms after 'all' are never evaluated.",
        ));
    }
    let direct = terms.iter().filter(|t| t.costs_lookup()).count();
    let count = lookups.unwrap_or(direct);
    let scope = if lookups.is_some() {
        ""
    } else {
        " (direct only)"
    };
    if count > SPF_LOOKUP_LIMIT {
        out.push(Finding::fail(
            "SPF lookups",
            format!(
                "{count} DNS lookups{scope}; the limit is {SPF_LOOKUP_LIMIT}. Receivers will return permerror."
            ),
        ));
    } else if count == SPF_LOOKUP_LIMIT {
        out.push(Finding::warn(
            "SPF lookups",
            format!("{count} of {SPF_LOOKUP_LIMIT} DNS lookups{scope}: no headroom left."),
        ));
    } else {
        out.push(Finding::ok(
            "SPF lookups",
            format!("{count} of {SPF_LOOKUP_LIMIT} DNS lookups{scope}."),
        ));
    }
    out
}

/// `k=v; k=v` tag lists, as used by DMARC and DKIM. Keys are lower-cased.
pub fn parse_tags(record: &str) -> BTreeMap<String, String> {
    record
        .split(';')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            Some((k.trim().to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect()
}

pub fn is_dmarc(txt: &str) -> bool {
    let t = txt.trim_start();
    t.len() >= 8 && t[..8].eq_ignore_ascii_case("v=DMARC1")
}

pub fn lint_dmarc(txts: &[String]) -> Vec<Finding> {
    let records: Vec<&String> = txts.iter().filter(|t| is_dmarc(t)).collect();
    let mut out = Vec::new();
    match records.len() {
        0 => {
            out.push(Finding::fail(
                "DMARC record",
                "No DMARC record at _dmarc.<domain>. Receivers have no policy for spoofed mail.",
            ));
            return out;
        }
        1 => out.push(Finding::ok(
            "DMARC record",
            "Exactly one DMARC record published.",
        )),
        n => {
            out.push(Finding::fail(
                "DMARC record",
                format!(
                    "{n} DMARC records found; receivers ignore the policy when there are several."
                ),
            ));
        }
    }
    let tags = parse_tags(records[0]);
    match tags.get("p").map(|p| p.to_ascii_lowercase()).as_deref() {
        Some("reject") => out.push(Finding::ok(
            "DMARC policy",
            "p=reject: failing mail is rejected.",
        )),
        Some("quarantine") => out.push(Finding::ok(
            "DMARC policy",
            "p=quarantine: failing mail goes to spam.",
        )),
        Some("none") => out.push(Finding::warn(
            "DMARC policy",
            "p=none only monitors. Move to quarantine or reject once reports look clean.",
        )),
        Some(other) => out.push(Finding::fail("DMARC policy", format!("Invalid p={other}."))),
        None => out.push(Finding::fail(
            "DMARC policy",
            "The required p= tag is missing.",
        )),
    }
    if let Some(pct) = tags.get("pct") {
        match pct.parse::<u8>() {
            Ok(100) => {}
            Ok(n) if n <= 100 => out.push(Finding::warn(
                "DMARC pct",
                format!("The policy applies to only {n}% of mail."),
            )),
            _ => out.push(Finding::fail("DMARC pct", format!("Invalid pct={pct}."))),
        }
    }
    if let Some(sp) = tags.get("sp") {
        out.push(Finding::info(
            "DMARC subdomains",
            format!("sp={sp} for subdomains."),
        ));
    }
    match tags.get("rua") {
        Some(rua) if rua.contains("mailto:") => out.push(Finding::ok(
            "DMARC reports",
            format!("Aggregate reports go to {rua}."),
        )),
        Some(rua) => out.push(Finding::warn(
            "DMARC reports",
            format!("rua={rua} has no mailto: address."),
        )),
        None => out.push(Finding::warn(
            "DMARC reports",
            "No rua= address, so you won't receive aggregate reports.",
        )),
    }
    out
}

pub fn lint_dkim(txts: &[String]) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(record) = txts.iter().find(|t| {
        let tags = parse_tags(t);
        tags.contains_key("p")
            || tags
                .get("v")
                .is_some_and(|v| v.eq_ignore_ascii_case("DKIM1"))
    }) else {
        out.push(Finding::fail(
            "DKIM record",
            "No DKIM key found at this selector.",
        ));
        return out;
    };
    let tags = parse_tags(record);
    out.push(Finding::ok("DKIM record", "A DKIM key is published."));
    let key: String = tags
        .get("p")
        .map(|p| p.chars().filter(|c| !c.is_whitespace()).collect())
        .unwrap_or_default();
    if key.is_empty() {
        out.push(Finding::fail(
            "DKIM key",
            "p= is empty: this key has been revoked.",
        ));
        return out;
    }
    let ed25519 = tags
        .get("k")
        .is_some_and(|k| k.eq_ignore_ascii_case("ed25519"));
    // Decoded size: 3 bytes per 4 base64 characters. A 1024-bit RSA public key
    // is ~162 bytes, 2048-bit ~294.
    let bytes = key.trim_end_matches('=').len() * 3 / 4;
    if ed25519 {
        out.push(Finding::ok("DKIM key", "Ed25519 key."));
    } else if bytes < 150 {
        out.push(Finding::fail("DKIM key", "RSA key shorter than 1024 bits."));
    } else if bytes < 250 {
        out.push(Finding::warn(
            "DKIM key",
            "About 1024 bits. 2048-bit keys are recommended.",
        ));
    } else {
        out.push(Finding::ok("DKIM key", "2048-bit or longer RSA key."));
    }
    if tags
        .get("t")
        .is_some_and(|t| t.split(':').any(|f| f.trim() == "y"))
    {
        out.push(Finding::warn(
            "DKIM testing",
            "t=y marks this key as being in test mode; receivers may ignore failures.",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;

    fn worst(f: &[Finding]) -> Severity {
        f.iter().map(|f| f.severity).max().unwrap()
    }

    fn txt(s: &str) -> Vec<String> {
        vec![s.to_string()]
    }

    #[test]
    fn spf_detection_needs_the_version_tag() {
        assert!(is_spf("v=spf1 -all"));
        assert!(is_spf("V=SPF1"));
        assert!(!is_spf("v=spf10 -all"));
        assert!(!is_spf("spf2.0/pra"));
    }

    #[test]
    fn spf_parses_mechanisms_and_modifiers() {
        let t =
            parse_spf("v=spf1 ip4:1.2.3.0/24 a/24 mx include:_spf.google.com redirect=x.com ~all")
                .unwrap();
        assert_eq!(t.len(), 6);
        assert_eq!(t[0].value.as_deref(), Some("1.2.3.0/24"));
        assert_eq!(t[1].name, "a");
        assert_eq!(t[3].include_target(), Some("_spf.google.com"));
        assert!(t[4].modifier && t[4].include_target() == Some("x.com"));
        assert_eq!(t[5].qualifier, '~');
        assert!(t.iter().filter(|t| t.costs_lookup()).count() == 4);
    }

    #[test]
    fn spf_rejects_unknown_mechanisms() {
        assert!(parse_spf("v=spf1 bogus -all").is_err());
        assert!(parse_spf("v=spf1 include -all").is_err());
        assert!(parse_spf("hello").is_err());
    }

    #[test]
    fn spf_lint_policies() {
        assert_eq!(worst(&lint_spf(&[], None)), Severity::Fail);
        assert_eq!(worst(&lint_spf(&txt("v=spf1 -all"), None)), Severity::Ok);
        assert_eq!(worst(&lint_spf(&txt("v=spf1 ?all"), None)), Severity::Warn);
        assert_eq!(worst(&lint_spf(&txt("v=spf1 +all"), None)), Severity::Fail);
        assert_eq!(
            worst(&lint_spf(&txt("v=spf1 a ptr -all"), None)),
            Severity::Warn
        );
        let two = vec!["v=spf1 -all".to_string(), "v=spf1 ~all".to_string()];
        assert_eq!(worst(&lint_spf(&two, None)), Severity::Fail);
    }

    #[test]
    fn spf_lookup_limit() {
        let r = txt("v=spf1 a -all");
        assert_eq!(worst(&lint_spf(&r, Some(10))), Severity::Warn);
        assert_eq!(worst(&lint_spf(&r, Some(11))), Severity::Fail);
        assert_eq!(worst(&lint_spf(&r, Some(3))), Severity::Ok);
    }

    #[test]
    fn dmarc_lint() {
        assert_eq!(worst(&lint_dmarc(&[])), Severity::Fail);
        let good = txt("v=DMARC1; p=reject; rua=mailto:d@example.com");
        assert_eq!(worst(&lint_dmarc(&good)), Severity::Ok);
        let none = txt("v=DMARC1; p=none; rua=mailto:d@example.com");
        assert_eq!(worst(&lint_dmarc(&none)), Severity::Warn);
        assert_eq!(
            worst(&lint_dmarc(&txt("v=DMARC1; rua=mailto:d@x.com"))),
            Severity::Fail
        );
        let partial = txt("v=DMARC1; p=quarantine; pct=25; rua=mailto:d@x.com");
        assert_eq!(worst(&lint_dmarc(&partial)), Severity::Warn);
    }

    #[test]
    fn dkim_lint() {
        assert_eq!(worst(&lint_dkim(&[])), Severity::Fail);
        assert_eq!(worst(&lint_dkim(&txt("v=DKIM1; p="))), Severity::Fail);
        let rsa2048 = format!("v=DKIM1; k=rsa; p={}", "A".repeat(392));
        assert_eq!(worst(&lint_dkim(&txt(&rsa2048))), Severity::Ok);
        let rsa1024 = format!("v=DKIM1; p={}", "A".repeat(216));
        assert_eq!(worst(&lint_dkim(&txt(&rsa1024))), Severity::Warn);
        let ed = format!("v=DKIM1; k=ed25519; p={}", "A".repeat(44));
        assert_eq!(worst(&lint_dkim(&txt(&ed))), Severity::Ok);
        let testing = format!("v=DKIM1; t=y; p={}", "A".repeat(392));
        assert_eq!(worst(&lint_dkim(&txt(&testing))), Severity::Warn);
    }

    #[test]
    fn tags_split_on_semicolons() {
        let t = parse_tags("v=DMARC1; p=none ;rua=mailto:a@b.c;");
        assert_eq!(t["p"], "none");
        assert_eq!(t["rua"], "mailto:a@b.c");
    }
}

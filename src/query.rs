//! What the user asked for: a check and a target, parsed from `check:target` style
//! input such as `mx:example.com` or `dkim:example.com:selector1`.

use std::net::IpAddr;

use color_eyre::eyre::{Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    A,
    Aaaa,
    Mx,
    Txt,
    Ns,
    Cname,
    Soa,
    Ptr,
    Caa,
    Spf,
    Dmarc,
    Dkim,
    Blacklist,
    Smtp,
    Whois,
    Http,
    Cert,
}

impl Check {
    pub const ALL: [Check; 17] = [
        Check::Mx,
        Check::A,
        Check::Aaaa,
        Check::Txt,
        Check::Ns,
        Check::Cname,
        Check::Soa,
        Check::Ptr,
        Check::Caa,
        Check::Spf,
        Check::Dmarc,
        Check::Dkim,
        Check::Blacklist,
        Check::Smtp,
        Check::Whois,
        Check::Http,
        Check::Cert,
    ];

    /// The prefix typed before the target: `mx:example.com`.
    pub fn prefix(self) -> &'static str {
        match self {
            Check::A => "a",
            Check::Aaaa => "aaaa",
            Check::Mx => "mx",
            Check::Txt => "txt",
            Check::Ns => "ns",
            Check::Cname => "cname",
            Check::Soa => "soa",
            Check::Ptr => "ptr",
            Check::Caa => "caa",
            Check::Spf => "spf",
            Check::Dmarc => "dmarc",
            Check::Dkim => "dkim",
            Check::Blacklist => "blacklist",
            Check::Smtp => "smtp",
            Check::Whois => "whois",
            Check::Http => "http",
            Check::Cert => "cert",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Check::A => "A",
            Check::Aaaa => "AAAA",
            Check::Mx => "MX",
            Check::Txt => "TXT",
            Check::Ns => "NS",
            Check::Cname => "CNAME",
            Check::Soa => "SOA",
            Check::Ptr => "PTR",
            Check::Caa => "CAA",
            Check::Spf => "SPF",
            Check::Dmarc => "DMARC",
            Check::Dkim => "DKIM",
            Check::Blacklist => "Blacklist",
            Check::Smtp => "SMTP",
            Check::Whois => "WHOIS",
            Check::Http => "HTTP",
            Check::Cert => "Cert",
        }
    }

    /// One line shown under the input box.
    pub fn hint(self) -> &'static str {
        match self {
            Check::A | Check::Aaaa => "IPv4/IPv6 addresses of a host",
            Check::Mx => "mail servers for a domain, and whether they resolve",
            Check::Txt => "all TXT records of a name",
            Check::Ns => "authoritative name servers",
            Check::Cname => "canonical name a host is an alias of",
            Check::Soa => "zone start of authority",
            Check::Ptr => "reverse DNS of an IP address (or of a host's address)",
            Check::Caa => "certificate authorities allowed to issue for a domain",
            Check::Spf => "SPF record, syntax and the 10-lookup limit",
            Check::Dmarc => "DMARC policy at _dmarc.<domain>",
            Check::Dkim => "DKIM key; dkim:domain:selector (common selectors if omitted)",
            Check::Blacklist => "DNS blocklists for an IP, or a host's addresses",
            Check::Smtp => "connect to the mail servers on port 25 and read the banner",
            Check::Whois => "registrar, dates and status of a domain or IP block",
            Check::Http => "http:// and https:// responses, redirects, HSTS",
            Check::Cert => "TLS certificate on port 443: chain, hostname, expiry",
        }
    }

    pub fn parse(prefix: &str) -> Option<Check> {
        let p = prefix.trim().to_ascii_lowercase();
        let p = match p.as_str() {
            "dnsbl" | "bl" | "blocklist" | "blacklists" => "blacklist",
            "rdns" | "reverse" => "ptr",
            "v6" => "aaaa",
            "https" | "web" | "url" => "http",
            "tls" | "ssl" | "certificate" => "cert",
            other => other,
        };
        Check::ALL.into_iter().find(|c| c.prefix() == p)
    }

    pub fn next(self) -> Check {
        let i = Check::ALL.iter().position(|c| *c == self).unwrap_or(0);
        Check::ALL[(i + 1) % Check::ALL.len()]
    }

    pub fn prev(self) -> Check {
        let i = Check::ALL.iter().position(|c| *c == self).unwrap_or(0);
        Check::ALL[(i + Check::ALL.len() - 1) % Check::ALL.len()]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub check: Check,
    /// A host name, or an IP address for `ptr` and `blacklist`.
    pub target: String,
    /// DKIM selector, when one was given.
    pub selector: Option<String>,
}

impl Query {
    /// The text that reproduces this query when typed back in.
    pub fn display(&self) -> String {
        match &self.selector {
            Some(s) => format!("{}:{}:{}", self.check.prefix(), self.target, s),
            None => format!("{}:{}", self.check.prefix(), self.target),
        }
    }
}

/// Reduce what people paste (URLs, `user@host`, trailing dots) to a bare host
/// name or IP address.
pub fn clean_target(raw: &str) -> String {
    let mut s = raw.trim();
    if let Some((_, rest)) = s.split_once("://") {
        s = rest;
    }
    s = s.split(['/', '?', '#']).next().unwrap_or(s);
    if let Some((_, host)) = s.rsplit_once('@') {
        s = host;
    }
    // Drop a :port, but leave IPv6 literals alone.
    if s.matches(':').count() == 1 {
        s = s.split(':').next().unwrap_or(s);
    }
    s.trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Parse `[check:]target[:selector]`. Without a prefix the `default` check is
/// used.
pub fn parse(input: &str, default: Check) -> Result<Query> {
    let input = input.trim();
    if input.is_empty() {
        bail!("type a domain or IP address first");
    }
    // A pasted URL means the web check, unless a prefix says otherwise.
    let (check, rest) = if input.starts_with("http://") || input.starts_with("https://") {
        (Check::Http, input)
    } else {
        match input.split_once(':') {
            Some((p, rest)) if Check::parse(p).is_some() => {
                (Check::parse(p).unwrap_or(default), rest)
            }
            _ => (default, input),
        }
    };
    let (target_raw, selector) = if check == Check::Dkim {
        match rest.split_once(':') {
            Some((t, s)) if !s.trim().is_empty() => (t, Some(s.trim().to_ascii_lowercase())),
            Some((t, _)) => (t, None),
            None => (rest, None),
        }
    } else {
        (rest, None)
    };
    let target = clean_target(target_raw);
    if target.is_empty() {
        bail!("{}: needs a domain or IP address", check.prefix());
    }
    let is_ip = target.parse::<IpAddr>().is_ok();
    if !is_ip && !valid_host(&target) {
        bail!("'{target}' is not a valid host name or IP address");
    }
    if is_ip
        && !matches!(
            check,
            Check::Ptr | Check::Blacklist | Check::Smtp | Check::Whois | Check::Http | Check::Cert
        )
    {
        bail!("{} needs a domain name, not an IP address", check.label());
    }
    if let Some(sel) = &selector
        && !valid_host(sel)
    {
        bail!("'{sel}' is not a valid DKIM selector");
    }
    Ok(Query {
        check,
        target,
        selector,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_selects_check() {
        let q = parse("mx:Example.COM", Check::A).unwrap();
        assert_eq!((q.check, q.target.as_str()), (Check::Mx, "example.com"));
        let q = parse("example.com", Check::Spf).unwrap();
        assert_eq!(q.check, Check::Spf);
        assert_eq!(
            parse("dnsbl:1.2.3.4", Check::Mx).unwrap().check,
            Check::Blacklist
        );
    }

    #[test]
    fn urls_emails_and_ports_are_cleaned() {
        assert_eq!(clean_target("https://Example.com/path?q=1"), "example.com");
        assert_eq!(clean_target("bob@mail.example.com"), "mail.example.com");
        assert_eq!(clean_target("example.com."), "example.com");
        assert_eq!(clean_target("example.com:8080"), "example.com");
        assert_eq!(clean_target("[2001:db8::1]"), "2001:db8::1");
    }

    #[test]
    fn dkim_takes_a_selector() {
        let q = parse("dkim:example.com:Selector1", Check::Mx).unwrap();
        assert_eq!(q.selector.as_deref(), Some("selector1"));
        assert_eq!(q.display(), "dkim:example.com:selector1");
        assert_eq!(parse("dkim:example.com", Check::Mx).unwrap().selector, None);
    }

    #[test]
    fn urls_mean_the_web_check_and_aliases_work() {
        let q = parse("https://Example.com/a?b=1", Check::Mx).unwrap();
        assert_eq!((q.check, q.target.as_str()), (Check::Http, "example.com"));
        assert_eq!(
            parse("tls:example.com", Check::Mx).unwrap().check,
            Check::Cert
        );
        assert_eq!(
            parse("https:example.com", Check::Mx).unwrap().check,
            Check::Http
        );
        assert!(parse("whois:192.0.2.1", Check::Mx).is_ok());
        assert!(parse("cert:192.0.2.1", Check::Mx).is_ok());
    }

    #[test]
    fn rejects_nonsense() {
        assert!(parse("", Check::Mx).is_err());
        assert!(parse("mx:", Check::Mx).is_err());
        assert!(parse("exa mple.com", Check::Mx).is_err());
        assert!(parse("-bad.example", Check::Mx).is_err());
        assert!(parse("mx:1.2.3.4", Check::Mx).is_err());
        assert!(parse("ptr:1.2.3.4", Check::Mx).is_ok());
    }

    #[test]
    fn cycling_wraps() {
        assert_eq!(Check::Cert.next(), Check::Mx);
        assert_eq!(Check::Mx.prev(), Check::Cert);
    }
}

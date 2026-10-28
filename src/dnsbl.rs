//! DNS blocklist helpers: the built-in zones and the reverse-IP query names.

use std::net::{IpAddr, Ipv4Addr};

/// Well-known, freely queryable IPv4 blocklists.
pub const ZONES: &[&str] = &[
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "psbl.surriel.com",
    "dnsbl-1.uceprotect.net",
    "dnsbl.dronebl.org",
    "all.s5h.net",
    "ix.dnsbl.manitu.net",
    "spam.dnsbl.anonmails.de",
    "dyna.spamrats.com",
    "noptr.spamrats.com",
    "spam.spamrats.com",
    "db.wpbl.info",
    "bl.nordspam.com",
    "dnsbl.spfbl.net",
];

/// `1.2.3.4` + `zen.spamhaus.org` → `4.3.2.1.zen.spamhaus.org.`
pub fn query_name(ip: Ipv4Addr, zone: &str) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.{}.", zone.trim_end_matches('.'))
}

/// The `in-addr.arpa` / `ip6.arpa` name for a PTR lookup.
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa.")
        }
        IpAddr::V6(v6) => {
            let mut name = String::new();
            for byte in v6.octets().iter().rev() {
                name.push_str(&format!("{:x}.{:x}.", byte & 0xf, byte >> 4));
            }
            name.push_str("ip6.arpa.");
            name
        }
    }
}

/// What a blocklist's answer means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Listed,
    /// The list refused the query (typically because it came from a public
    /// resolver), so it says nothing about the address.
    Refused,
}

/// Interpret an A record returned by a blocklist. Everything in 127.0.0.0/8 is
/// a listing, except Spamhaus-style 127.255.255.x codes, which are errors.
pub fn verdict(answer: Ipv4Addr) -> Option<Verdict> {
    let o = answer.octets();
    match o {
        [127, 255, 255, _] => Some(Verdict::Refused),
        [127, ..] => Some(Verdict::Listed),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_reversed() {
        assert_eq!(
            query_name("1.2.3.4".parse().unwrap(), "zen.spamhaus.org"),
            "4.3.2.1.zen.spamhaus.org."
        );
        assert_eq!(
            reverse_name("1.2.3.4".parse().unwrap()),
            "4.3.2.1.in-addr.arpa."
        );
        assert_eq!(
            reverse_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
    }

    #[test]
    fn spamhaus_error_codes_are_not_listings() {
        assert_eq!(verdict("127.0.0.2".parse().unwrap()), Some(Verdict::Listed));
        assert_eq!(
            verdict("127.255.255.254".parse().unwrap()),
            Some(Verdict::Refused)
        );
        assert_eq!(verdict("8.8.8.8".parse().unwrap()), None);
    }
}

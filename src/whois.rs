//! WHOIS over port 43: find the right server via IANA, follow a registrar
//! referral, and pull the interesting fields out of the free-form text.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use color_eyre::eyre::{Result, WrapErr, bail, eyre};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

pub const IANA: &str = "whois.iana.org";
/// Replies are free text from third parties; don't buffer unbounded amounts.
const MAX_REPLY: u64 = 256 * 1024;
/// IANA, the registry, then the registrar.
const MAX_HOPS: usize = 3;

/// Ask one server one question and return everything it says.
pub async fn ask(server: &str, port: u16, question: &str, limit: Duration) -> Result<String> {
    let mut stream = timeout(limit, TcpStream::connect((server, port)))
        .await
        .map_err(|_| eyre!("timed out connecting to {server}"))?
        .wrap_err_with(|| format!("cannot connect to {server}"))?;
    stream
        .write_all(format!("{question}\r\n").as_bytes())
        .await?;
    let mut buf = Vec::new();
    timeout(limit, (&mut stream).take(MAX_REPLY).read_to_end(&mut buf))
        .await
        .map_err(|_| eyre!("{server} stopped answering"))??;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// A referral names a host to connect to, and comes from a remote server, so
/// only plain DNS names are followed (no IP literals, no single labels).
pub fn is_referral_host(host: &str) -> bool {
    host.contains('.')
        && host.parse::<std::net::IpAddr>().is_err()
        && host.len() <= 253
        && host
            .split('.')
            .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// `Key: value` lines, skipping comments and banners.
pub fn fields(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with(['%', '#', '>', '-']))
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            let (k, v) = (k.trim(), v.trim());
            (!k.is_empty() && !v.is_empty() && k.len() < 48 && !k.contains("http"))
                .then(|| (k.to_ascii_lowercase(), v.to_string()))
        })
        .collect()
}

fn first(fields: &[(String, String)], keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| fields.iter().find(|(f, _)| f == k).map(|(_, v)| v.clone()))
}

fn all(fields: &[(String, String)], keys: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (f, v) in fields {
        if keys.contains(&f.as_str()) {
            let v = v
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if !v.is_empty() && !out.contains(&v) {
                out.push(v);
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub registrar: Option<String>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub expires: Option<String>,
    pub status: Vec<String>,
    pub nameservers: Vec<String>,
    pub dnssec: Option<String>,
    /// IP allocations: range, network name, organisation, country.
    pub range: Option<String>,
    pub net_name: Option<String>,
    pub org: Option<String>,
    pub country: Option<String>,
}

pub fn summarize(text: &str) -> Summary {
    let f = fields(text);
    let status = f
        .iter()
        .filter(|(k, _)| k == "domain status" || k == "status")
        // "clientTransferProhibited https://icann.org/epp#..." → first word.
        .filter_map(|(_, v)| v.split_whitespace().next().map(str::to_string))
        .fold(Vec::new(), |mut acc, s| {
            if !acc.contains(&s) {
                acc.push(s);
            }
            acc
        });
    Summary {
        registrar: first(&f, &["registrar", "sponsoring registrar"]),
        created: first(
            &f,
            &[
                "creation date",
                "created",
                "registered",
                "registration time",
                "domain registered",
            ],
        ),
        updated: first(
            &f,
            &[
                "updated date",
                "last updated",
                "last-modified",
                "changed",
                "last modified",
            ],
        ),
        expires: first(
            &f,
            &[
                "registry expiry date",
                "registrar registration expiration date",
                "expiry date",
                "expiration date",
                "expires",
                "paid-till",
                "renewal date",
            ],
        ),
        status,
        nameservers: all(&f, &["name server", "nserver"]),
        dnssec: first(&f, &["dnssec"]),
        range: first(&f, &["netrange", "inetnum", "inet6num"]),
        net_name: first(&f, &["netname"]),
        org: first(
            &f,
            &["orgname", "organization", "org-name", "owner", "descr"],
        ),
        country: first(&f, &["country"]),
    }
}

/// The server a response points at (`refer:` from IANA, `Registrar WHOIS
/// Server:` from a thin registry).
pub fn referral(text: &str) -> Option<String> {
    let f = fields(text);
    let host = first(
        &f,
        &["refer", "whois", "registrar whois server", "referralserver"],
    )?;
    let host = host
        .trim_start_matches("whois://")
        .trim_start_matches("rwhois://")
        .split([':', '/'])
        .next()?
        .trim()
        .to_ascii_lowercase();
    is_referral_host(&host).then_some(host)
}

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The day number (since the epoch) of a WHOIS date: `2030-08-13`,
/// `2030-08-13T04:00:00Z`, `13-aug-2030` or `2030.08.13`.
pub fn parse_day(text: &str) -> Option<i64> {
    let t = text.trim();
    let head = t.split(['T', ' ']).next()?;
    let num = |s: &str| s.parse::<i64>().ok();
    let parts: Vec<&str> = head.split(['-', '.', '/']).collect();
    let months = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let month = |s: &str| {
        num(s).or_else(|| {
            months
                .iter()
                .position(|m| s.len() >= 3 && s[..3].eq_ignore_ascii_case(m))
                .map(|i| i as i64 + 1)
        })
    };
    let (y, m, d) = match parts.as_slice() {
        [y, m, d] if y.len() == 4 => (num(y)?, month(m)?, num(d)?),
        [d, m, y] if y.len() == 4 => (num(y)?, month(m)?, num(d)?),
        _ => return None,
    };
    ((1..=12).contains(&m) && (1..=31).contains(&d)).then(|| days_from_civil(y, m, d))
}

pub fn today() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    (secs / 86_400) as i64
}

/// Whether a reply says the name is not registered.
pub fn is_no_match(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    [
        "no match",
        "not found",
        "no entries found",
        "no data found",
        "status: free",
        "status: available",
        "is free",
    ]
    .iter()
    .any(|p| t.contains(p))
}

/// The server chain and the last (most specific) answer.
pub struct Answer {
    pub servers: Vec<String>,
    pub text: String,
}

/// Look up a domain or IP, following referrals.
pub async fn lookup(target: &str, limit: Duration) -> Result<Answer> {
    let mut server = IANA.to_string();
    let mut servers = Vec::new();
    let mut text = String::new();
    for _ in 0..MAX_HOPS {
        let reply = ask(&server, 43, target, limit).await?;
        servers.push(server.clone());
        let next = referral(&reply).filter(|n| *n != server && !servers.contains(n));
        // IANA's own answer only says where to go; keep it only if it's all we get.
        if server != IANA || next.is_none() {
            text = reply;
        }
        match next {
            Some(n) => server = n,
            None => break,
        }
    }
    if text.trim().is_empty() {
        bail!(
            "{} returned nothing",
            servers.last().map_or("the server", String::as_str)
        );
    }
    Ok(Answer { servers, text })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COM: &str = "\
   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.registrar.example
   Updated Date: 2024-08-14T07:01:34Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2030-08-13T04:00:00Z
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
>>> Last update of whois database: 2025-01-01T00:00:00Z <<<
";

    #[test]
    fn summarizes_a_thin_registry_reply() {
        let s = summarize(COM);
        assert_eq!(
            s.registrar.as_deref(),
            Some("RESERVED-Internet Assigned Numbers Authority")
        );
        assert_eq!(s.expires.as_deref(), Some("2030-08-13T04:00:00Z"));
        assert_eq!(
            s.status,
            ["clientDeleteProhibited", "clientTransferProhibited"]
        );
        assert_eq!(s.nameservers, ["a.iana-servers.net", "b.iana-servers.net"]);
        assert_eq!(s.dnssec.as_deref(), Some("signedDelegation"));
    }

    #[test]
    fn summarizes_an_ip_allocation() {
        let s = summarize(
            "% RIPE\ninetnum: 192.0.2.0 - 192.0.2.255\nnetname: TEST-NET\ncountry: NL\ndescr: Docs\n",
        );
        assert_eq!(s.range.as_deref(), Some("192.0.2.0 - 192.0.2.255"));
        assert_eq!(s.net_name.as_deref(), Some("TEST-NET"));
        assert_eq!(s.org.as_deref(), Some("Docs"));
        assert_eq!(s.country.as_deref(), Some("NL"));
    }

    #[test]
    fn follows_referrals_only_to_plain_hostnames() {
        assert_eq!(
            referral("refer: whois.verisign-grs.com\n").as_deref(),
            Some("whois.verisign-grs.com")
        );
        assert_eq!(referral(COM).as_deref(), Some("whois.registrar.example"));
        assert_eq!(
            referral("ReferralServer: whois://whois.arin.net:43\n").as_deref(),
            Some("whois.arin.net")
        );
        for bad in ["127.0.0.1", "localhost", "a b.example", "10.0.0.1"] {
            assert_eq!(referral(&format!("refer: {bad}\n")), None, "{bad}");
        }
    }

    #[test]
    fn dates_parse_in_common_formats() {
        let d = parse_day("2000-03-01").unwrap();
        assert_eq!(parse_day("2000-03-02T10:00:00Z"), Some(d + 1));
        assert_eq!(parse_day("01-mar-2000"), Some(d));
        assert_eq!(parse_day("2000.03.01"), Some(d));
        assert_eq!(parse_day("1970-01-01"), Some(0));
        assert_eq!(
            parse_day("2024-02-29").map(|x| x + 1),
            parse_day("2024-03-01")
        );
        assert_eq!(parse_day("soon"), None);
        assert_eq!(parse_day("2000-13-01"), None);
    }

    #[test]
    fn detects_unregistered_names() {
        assert!(is_no_match("No match for \"WWW.EXAMPLE.COM\".\n"));
        assert!(is_no_match("% Nothing\nstatus: FREE\n"));
        assert!(!is_no_match(COM));
    }

    #[tokio::test]
    async fn asks_a_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"example.com\r\n");
            sock.write_all(b"Registrar: Test\n").await.unwrap();
        });
        let text = ask("127.0.0.1", port, "example.com", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(summarize(&text).registrar.as_deref(), Some("Test"));
    }
}

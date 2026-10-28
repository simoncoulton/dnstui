//! Runs a [`Query`] against DNS (and, for `smtp`, port 25) and returns a
//! plain-data [`Report`]. Nothing in here knows about the terminal.

use std::{
    collections::BTreeSet,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    time::{Duration, Instant},
};

use color_eyre::eyre::{Result, eyre};
use futures::{StreamExt, stream};
use hickory_resolver::{
    Resolver, TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    net::{NetError, runtime::TokioRuntimeProvider},
    proto::rr::{RData, Record, RecordType},
    system_conf,
};

use crate::{
    config::Config,
    dnsbl::{self, Verdict},
    email, fmt,
    query::{Check, Query},
    report::{Finding, Report, Severity},
    smtp, web, whois,
};

/// Selectors tried when `dkim:` names none.
const COMMON_SELECTORS: &[&str] = &[
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "s1",
    "s2",
    "mail",
    "dkim",
    "smtp",
    "mandrill",
    "mxvault",
    "everlytickey1",
    "cm",
    "zoho",
    "protonmail",
    "fm1",
];

/// Redirects followed per scheme.
const MAX_REDIRECTS: usize = 6;
/// Six months, in seconds: the shortest HSTS lifetime considered healthy.
const HSTS_MIN: u64 = 15_768_000;

/// Total lookups an SPF count may chase before giving up.
const SPF_WALK_LIMIT: usize = 40;

pub struct Engine {
    resolver: TokioResolver,
    timeout: Duration,
    server: String,
    selectors: Vec<String>,
    zones: Vec<String>,
}

enum Lookup {
    Records(Vec<Record>),
    /// The name exists (or not) but holds no records of this type.
    Empty {
        nxdomain: bool,
    },
    Failed(String),
}

impl Lookup {
    fn records(self) -> Vec<Record> {
        match self {
            Lookup::Records(r) => r,
            _ => Vec::new(),
        }
    }
}

/// TXT strings of a record joined the way resolvers present them.
fn txt_text(strings: &[Box<[u8]>]) -> String {
    strings
        .iter()
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

fn txt_values(records: &[Record]) -> Vec<String> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::TXT(t) => Some(txt_text(&t.txt_data)),
            _ => None,
        })
        .collect()
}

fn trim_dot(name: impl std::fmt::Display) -> String {
    let s = name.to_string();
    s.strip_suffix('.').map(str::to_string).unwrap_or(s)
}

fn fqdn(name: &str) -> String {
    format!("{}.", name.trim_end_matches('.'))
}

fn shorten(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

impl Engine {
    pub fn new(config: &Config, server: Option<IpAddr>) -> Result<Self> {
        let server = server.or(config.dns_server);
        let mut builder = match server {
            Some(ip) => Resolver::builder_with_config(
                ResolverConfig::from_parts(None, vec![], vec![NameServerConfig::udp_and_tcp(ip)]),
                TokioRuntimeProvider::default(),
            ),
            None => {
                let (system, opts) = system_conf::read_system_conf()
                    .map_err(|e| eyre!("cannot read the system DNS configuration: {e}"))?;
                let (_, _, servers) = system.into_parts();
                // Query names are always fully qualified, so the search list is moot.
                Resolver::builder_with_config(
                    ResolverConfig::from_parts(None, vec![], with_tcp_fallback(servers)),
                    TokioRuntimeProvider::default(),
                )
                .with_options(opts)
            }
        };
        let opts = builder.options_mut();
        opts.timeout = config.timeout();
        opts.attempts = 2;
        // Every run should see the zone as it is now, not a cached answer.
        opts.cache_size = 0;
        opts.ndots = 0;
        // With several servers queried in parallel, one truncated UDP answer
        // switches the pool to TCP and the other server's truncated answer is
        // then taken as final, so long TXT/SPF sets fail with "response was
        // truncated". One request at a time retries over TCP correctly.
        opts.num_concurrent_reqs = 1;
        let resolver = builder
            .build()
            .map_err(|e| eyre!("cannot start the resolver: {e}"))?;
        Ok(Self {
            resolver,
            timeout: config.timeout(),
            server: server.map_or_else(|| "system resolver".to_string(), |ip| ip.to_string()),
            selectors: config
                .dkim_selectors
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            zones: config
                .blacklists
                .iter()
                .map(|z| z.trim().to_string())
                .collect(),
        })
    }

    async fn lookup(&self, name: &str, rt: RecordType) -> Lookup {
        match self.resolver.lookup(fqdn(name), rt).await {
            Ok(l) => {
                let records: Vec<Record> = l
                    .answers()
                    .iter()
                    .filter(|r| r.record_type() == rt)
                    .cloned()
                    .collect();
                if records.is_empty() {
                    Lookup::Empty { nxdomain: false }
                } else {
                    Lookup::Records(records)
                }
            }
            Err(e) if e.is_nx_domain() => Lookup::Empty { nxdomain: true },
            Err(e) if e.is_no_records_found() => Lookup::Empty { nxdomain: false },
            Err(e) => Lookup::Failed(e.to_string()),
        }
    }

    /// A and AAAA addresses of a host, v4 first.
    async fn addresses(&self, host: &str) -> Vec<IpAddr> {
        if let Ok(ip) = host.parse() {
            return vec![ip];
        }
        let (a, aaaa) = futures::join!(
            self.lookup(host, RecordType::A),
            self.lookup(host, RecordType::AAAA)
        );
        let mut out = Vec::new();
        for r in a.records().into_iter().chain(aaaa.records()) {
            match r.data {
                RData::A(a) => out.push(IpAddr::V4(a.0)),
                RData::AAAA(a) => out.push(IpAddr::V6(a.0)),
                _ => {}
            }
        }
        out
    }

    pub async fn run(&self, query: Query) -> Report {
        let started = Instant::now();
        let mut report = Report::new(query.clone());
        report.server = self.server.clone();
        match query.check {
            Check::A => self.simple(&mut report, RecordType::A).await,
            Check::Aaaa => self.simple(&mut report, RecordType::AAAA).await,
            Check::Txt => self.simple(&mut report, RecordType::TXT).await,
            Check::Cname => self.simple(&mut report, RecordType::CNAME).await,
            Check::Caa => self.simple(&mut report, RecordType::CAA).await,
            Check::Soa => self.soa(&mut report).await,
            Check::Ns => self.ns(&mut report).await,
            Check::Mx => self.mx(&mut report).await,
            Check::Ptr => self.ptr(&mut report).await,
            Check::Spf => self.spf(&mut report).await,
            Check::Dmarc => self.dmarc(&mut report).await,
            Check::Dkim => self.dkim(&mut report).await,
            Check::Blacklist => self.blacklist(&mut report).await,
            Check::Smtp => self.smtp(&mut report).await,
            Check::Whois => self.whois(&mut report).await,
            Check::Http => self.http(&mut report).await,
            Check::Cert => self.cert(&mut report).await,
        }
        report.elapsed = started.elapsed();
        report
    }

    /// Add the finding for a lookup that produced no records.
    fn explain_empty(
        report: &mut Report,
        what: &str,
        name: &str,
        outcome: &Lookup,
        missing: Severity,
    ) {
        match outcome {
            Lookup::Empty { nxdomain: true } => {
                report.findings.push(Finding::fail(
                    "DNS lookup",
                    format!("{name} does not exist (NXDOMAIN)."),
                ));
            }
            Lookup::Empty { nxdomain: false } => {
                report.findings.push(Finding::new(
                    missing,
                    "DNS lookup",
                    format!("{name} has no {what} records."),
                ));
            }
            Lookup::Failed(e) => report
                .findings
                .push(Finding::fail("DNS lookup", format!("{name}: {e}"))),
            Lookup::Records(_) => {}
        }
    }

    async fn simple(&self, report: &mut Report, rt: RecordType) {
        let name = report.query.target.clone();
        let outcome = self.lookup(&name, rt).await;
        report.columns = vec!["Name", "Type", "TTL", "Value"];
        if let Lookup::Records(records) = &outcome {
            for r in records {
                report.rows.push(vec![
                    trim_dot(&r.name),
                    rt.to_string(),
                    r.ttl.to_string(),
                    rdata_text(&r.data),
                ]);
            }
            report.findings.push(Finding::ok(
                format!("{rt} records"),
                format!("{} record(s) found.", records.len()),
            ));
        } else {
            let missing = if matches!(rt, RecordType::CNAME | RecordType::CAA) {
                Severity::Info
            } else {
                Severity::Fail
            };
            Self::explain_empty(report, &rt.to_string(), &name, &outcome, missing);
        }
        if rt == RecordType::CAA && report.rows.is_empty() && report.worst() < Severity::Fail {
            report.findings.push(Finding::info(
                "CAA",
                "No CAA records, so any certificate authority may issue for this domain.",
            ));
        }
    }

    async fn soa(&self, report: &mut Report) {
        let name = report.query.target.clone();
        let outcome = self.lookup(&name, RecordType::SOA).await;
        report.columns = vec!["Field", "Value"];
        if let Lookup::Records(records) = &outcome {
            for r in records {
                if let RData::SOA(s) = &r.data {
                    for (k, v) in [
                        ("Primary server", trim_dot(&s.mname)),
                        ("Admin mailbox", trim_dot(&s.rname)),
                        ("Serial", s.serial.to_string()),
                        ("Refresh", format!("{}s", s.refresh)),
                        ("Retry", format!("{}s", s.retry)),
                        ("Expire", format!("{}s", s.expire)),
                        ("Minimum TTL", format!("{}s", s.minimum)),
                    ] {
                        report.rows.push(vec![k.into(), v]);
                    }
                    report.findings.push(Finding::ok(
                        "SOA record",
                        format!("Zone served by {}.", trim_dot(&s.mname)),
                    ));
                }
            }
        } else {
            Self::explain_empty(report, "SOA", &name, &outcome, Severity::Fail);
        }
    }

    /// Resolve each host to addresses concurrently, keeping the input order.
    async fn resolve_all(&self, hosts: &[String]) -> Vec<Vec<IpAddr>> {
        bounded(hosts.iter().map(|h| self.addresses(h)).collect(), 8).await
    }

    async fn ns(&self, report: &mut Report) {
        let name = report.query.target.clone();
        let outcome = self.lookup(&name, RecordType::NS).await;
        report.columns = vec!["Name server", "Addresses", "TTL"];
        let Lookup::Records(records) = &outcome else {
            Self::explain_empty(report, "NS", &name, &outcome, Severity::Fail);
            return;
        };
        let mut hosts = Vec::new();
        for r in records {
            if let RData::NS(ns) = &r.data {
                hosts.push((trim_dot(&ns.0), r.ttl));
            }
        }
        let names: Vec<String> = hosts.iter().map(|(h, _)| h.clone()).collect();
        let addrs = self.resolve_all(&names).await;
        for ((host, ttl), ips) in hosts.iter().zip(&addrs) {
            report
                .rows
                .push(vec![host.clone(), join_ips(ips), ttl.to_string()]);
            if ips.is_empty() {
                report.findings.push(Finding::fail(
                    "NS address",
                    format!("{host} does not resolve to an address."),
                ));
            }
        }
        match hosts.len() {
            0 => {}
            1 => report.findings.push(Finding::warn(
                "NS count",
                "Only one name server; RFC 2182 asks for at least two.",
            )),
            n => report
                .findings
                .push(Finding::ok("NS count", format!("{n} name servers."))),
        }
    }

    async fn mx(&self, report: &mut Report) {
        let name = report.query.target.clone();
        let outcome = self.lookup(&name, RecordType::MX).await;
        report.columns = vec!["Pref", "Mail server", "Addresses", "TTL"];
        let Lookup::Records(records) = &outcome else {
            Self::explain_empty(report, "MX", &name, &outcome, Severity::Fail);
            return;
        };
        let mut mx: Vec<(u16, String, u32)> = records
            .iter()
            .filter_map(|r| match &r.data {
                RData::MX(m) => Some((m.preference, trim_dot(&m.exchange), r.ttl)),
                _ => None,
            })
            .collect();
        mx.sort();
        if mx.len() == 1 && mx[0].1.is_empty() {
            report.rows.push(vec![
                mx[0].0.to_string(),
                ". (null MX)".into(),
                String::new(),
                mx[0].2.to_string(),
            ]);
            report.findings.push(Finding::info(
                "Null MX",
                "This domain says it accepts no mail (RFC 7505).",
            ));
            return;
        }
        let hosts: Vec<String> = mx.iter().map(|(_, h, _)| h.clone()).collect();
        let addrs = self.resolve_all(&hosts).await;
        let mut unresolved = 0;
        for ((pref, host, ttl), ips) in mx.iter().zip(&addrs) {
            report.rows.push(vec![
                pref.to_string(),
                host.clone(),
                join_ips(ips),
                ttl.to_string(),
            ]);
            if ips.is_empty() {
                unresolved += 1;
                report.findings.push(Finding::fail(
                    "MX address",
                    format!("{host} does not resolve to an address."),
                ));
            }
        }
        if unresolved == 0 {
            report.findings.push(Finding::ok(
                "MX hosts",
                "Every mail server resolves to an address.",
            ));
        }
        match mx.len() {
            1 => report.findings.push(Finding::warn(
                "MX redundancy",
                "Only one mail server; there is no fallback if it is down.",
            )),
            n => report
                .findings
                .push(Finding::ok("MX redundancy", format!("{n} mail servers."))),
        }
        let prefs: BTreeSet<u16> = mx.iter().map(|(p, _, _)| *p).collect();
        if prefs.len() == 1 && mx.len() > 1 {
            report.findings.push(Finding::info(
                "MX priority",
                "All servers share one preference, so mail is load-balanced between them.",
            ));
        }
    }

    async fn ptr(&self, report: &mut Report) {
        let target = report.query.target.clone();
        report.columns = vec!["Address", "Reverse name", "Resolves back"];
        let ips = self.addresses(&target).await;
        if ips.is_empty() {
            report.findings.push(Finding::fail(
                "DNS lookup",
                format!("{target} does not resolve to an address."),
            ));
            return;
        }
        for ip in ips {
            let outcome = self.lookup(&dnsbl::reverse_name(ip), RecordType::PTR).await;
            match outcome {
                Lookup::Records(records) => {
                    for r in records {
                        let RData::PTR(p) = &r.data else { continue };
                        let host = trim_dot(&p.0);
                        let back = self.addresses(&host).await;
                        let confirmed = back.contains(&ip);
                        report.rows.push(vec![
                            ip.to_string(),
                            host.clone(),
                            if confirmed { "yes".into() } else { "no".into() },
                        ]);
                        report.findings.push(if confirmed {
                            Finding::ok("Forward-confirmed rDNS", format!("{ip} → {host} → {ip}."))
                        } else {
                            Finding::warn(
                                "Forward-confirmed rDNS",
                                format!("{host} does not resolve back to {ip}; mail servers often reject this."),
                            )
                        });
                    }
                }
                Lookup::Empty { .. } => {
                    report
                        .rows
                        .push(vec![ip.to_string(), "-".into(), "-".into()]);
                    report.findings.push(Finding::warn(
                        "Reverse DNS",
                        format!("{ip} has no PTR record."),
                    ));
                }
                Lookup::Failed(e) => report
                    .findings
                    .push(Finding::fail("Reverse DNS", format!("{ip}: {e}"))),
            }
        }
    }

    /// The SPF TXT strings published at `domain`.
    async fn spf_txts(&self, domain: &str) -> Result<Vec<String>, String> {
        match self.lookup(domain, RecordType::TXT).await {
            Lookup::Records(r) => Ok(txt_values(&r)),
            Lookup::Empty { .. } => Ok(Vec::new()),
            Lookup::Failed(e) => Err(e),
        }
    }

    /// DNS lookups an SPF record costs, following includes and redirects.
    fn spf_count<'a>(
        &'a self,
        domain: String,
        depth: usize,
        budget: &'a mut usize,
    ) -> Pin<Box<dyn Future<Output = usize> + Send + 'a>> {
        Box::pin(async move {
            let Ok(txts) = self.spf_txts(&domain).await else {
                return 0;
            };
            let Some(record) = txts.iter().find(|t| email::is_spf(t)) else {
                return 0;
            };
            let Ok(terms) = email::parse_spf(record) else {
                return 0;
            };
            let mut count = 0;
            for term in terms.iter().filter(|t| t.costs_lookup()) {
                count += 1;
                if let Some(next) = term.include_target()
                    && depth < 10
                    && *budget > 0
                {
                    *budget -= 1;
                    count += self.spf_count(next.to_string(), depth + 1, budget).await;
                }
            }
            count
        })
    }

    async fn spf(&self, report: &mut Report) {
        let name = report.query.target.clone();
        report.columns = vec!["Qualifier", "Mechanism", "Value"];
        let txts = match self.spf_txts(&name).await {
            Ok(t) => t,
            Err(e) => {
                report
                    .findings
                    .push(Finding::fail("DNS lookup", format!("{name}: {e}")));
                return;
            }
        };
        let mut lookups = None;
        if let Some(record) = txts.iter().find(|t| email::is_spf(t)) {
            report
                .rows
                .push(vec!["".into(), "record".into(), record.clone()]);
            if let Ok(terms) = email::parse_spf(record) {
                for t in &terms {
                    let q = if t.modifier {
                        "modifier"
                    } else {
                        match t.qualifier {
                            '-' => "fail",
                            '~' => "softfail",
                            '?' => "neutral",
                            _ => "pass",
                        }
                    };
                    report.rows.push(vec![
                        q.into(),
                        t.name.clone(),
                        t.value.clone().unwrap_or_default(),
                    ]);
                }
                let mut budget = SPF_WALK_LIMIT;
                lookups = Some(self.spf_count(name.clone(), 0, &mut budget).await);
            }
        }
        report.findings.extend(email::lint_spf(&txts, lookups));
    }

    async fn dmarc(&self, report: &mut Report) {
        let name = report.query.target.clone();
        let dmarc_name = format!("_dmarc.{name}");
        report.columns = vec!["Tag", "Value"];
        let txts = match self.lookup(&dmarc_name, RecordType::TXT).await {
            Lookup::Failed(e) => {
                report
                    .findings
                    .push(Finding::fail("DNS lookup", format!("{dmarc_name}: {e}")));
                return;
            }
            other => txt_values(&other.records()),
        };
        if let Some(record) = txts.iter().find(|t| email::is_dmarc(t)) {
            for (k, v) in email::parse_tags(record) {
                report.rows.push(vec![k, v]);
            }
        }
        report.findings.extend(email::lint_dmarc(&txts));
    }

    async fn dkim(&self, report: &mut Report) {
        let name = report.query.target.clone();
        report.columns = vec!["Selector", "Record"];
        let selectors: Vec<String> = match &report.query.selector {
            Some(s) => vec![s.clone()],
            None => COMMON_SELECTORS
                .iter()
                .map(|s| s.to_string())
                .chain(self.selectors.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        };
        let explicit = report.query.selector.is_some();
        let futures = selectors.iter().map(|sel| {
            let name = &name;
            async move {
                let host = format!("{sel}._domainkey.{name}");
                (
                    sel.clone(),
                    txt_values(&self.lookup(&host, RecordType::TXT).await.records()),
                )
            }
        });
        let found: Vec<(String, Vec<String>)> = bounded(futures.collect(), 8)
            .await
            .into_iter()
            .filter(|(_, t)| !t.is_empty())
            .collect();
        if found.is_empty() {
            report.findings.push(Finding::fail(
                "DKIM record",
                if explicit {
                    format!("No DKIM key at {}._domainkey.{name}.", selectors[0])
                } else {
                    format!(
                        "None of {} common selectors has a key. Try dkim:{name}:<selector> with the selector from a message's DKIM-Signature header (s=).",
                        selectors.len()
                    )
                },
            ));
            return;
        }
        for (sel, txts) in &found {
            report.rows.push(vec![sel.clone(), txts.join(" ")]);
            for mut f in email::lint_dkim(txts) {
                f.title = format!("{} [{sel}]", f.title);
                report.findings.push(f);
            }
        }
    }

    async fn blacklist(&self, report: &mut Report) {
        let target = report.query.target.clone();
        report.columns = vec!["Address", "Blocklist", "Result"];
        let all = self.addresses(&target).await;
        let v4: Vec<_> = all
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            })
            .collect();
        if v4.is_empty() {
            let why = if all.is_empty() {
                "does not resolve to an address"
            } else {
                "has only IPv6 addresses, which these lists don't cover"
            };
            report
                .findings
                .push(Finding::fail("Blocklists", format!("{target} {why}.")));
            return;
        }
        let zones: Vec<String> = dnsbl::ZONES
            .iter()
            .map(|z| z.to_string())
            .chain(self.zones.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let pairs: Vec<_> = v4
            .iter()
            .flat_map(|ip| zones.iter().map(move |z| (*ip, z.clone())))
            .collect();
        let futures = pairs.into_iter().map(|(ip, zone)| async move {
            let outcome = match self
                .resolver
                .lookup(dnsbl::query_name(ip, &zone), RecordType::A)
                .await
            {
                Ok(l) => {
                    let verdict = l.answers().iter().find_map(|r| match &r.data {
                        RData::A(a) => dnsbl::verdict(a.0).map(|v| (v, a.0)),
                        _ => None,
                    });
                    match verdict {
                        Some((Verdict::Listed, code)) => format!("LISTED ({code})"),
                        Some((Verdict::Refused, _)) => "refused".to_string(),
                        None => "not listed".to_string(),
                    }
                }
                Err(e) if e.is_nx_domain() || e.is_no_records_found() => "not listed".to_string(),
                Err(NetError::Timeout) => "timeout".to_string(),
                Err(_) => "error".to_string(),
            };
            (ip, zone, outcome)
        });
        let results: Vec<_> = bounded(futures.collect(), 16).await;
        let count = |pred: fn(&str) -> bool| results.iter().filter(|(_, _, r)| pred(r)).count();
        let listed = count(|r| r.starts_with("LISTED"));
        let refused = count(|r| r == "refused");
        let failed = count(|r| r == "timeout" || r == "error");
        for (ip, zone, outcome) in &results {
            report
                .rows
                .push(vec![ip.to_string(), zone.clone(), outcome.clone()]);
        }
        // Listings first, then the rest in list order.
        report.rows.sort_by_key(|r| !r[2].starts_with("LISTED"));
        let total = zones.len() * v4.len();
        if listed > 0 {
            report.findings.push(Finding::fail(
                "Blocklists",
                format!("Listed on {listed} of {total} checks."),
            ));
        } else {
            report.findings.push(Finding::ok(
                "Blocklists",
                format!(
                    "Not listed on {} of {total} checks.",
                    total - refused - failed
                ),
            ));
        }
        if refused > 0 {
            report.findings.push(Finding::warn(
                "Refused queries",
                format!("{refused} list(s) refused the query, usually because it came through a large public resolver. Set dns_server to your own resolver and retry."),
            ));
        }
        if failed > 0 {
            report.findings.push(Finding::info(
                "Unanswered",
                format!("{failed} list(s) timed out or errored."),
            ));
        }
    }

    async fn whois(&self, report: &mut Report) {
        let target = report.query.target.clone();
        report.columns = vec!["Field", "Value"];
        let is_ip = target.parse::<IpAddr>().is_ok();
        // A subdomain has no WHOIS record of its own; try its parents.
        let mut name = target.clone();
        let answer = loop {
            match whois::lookup(&name, self.timeout).await {
                Ok(a)
                    if !is_ip && whois::is_no_match(&a.text) && name.matches('.').count() >= 2 =>
                {
                    name = name
                        .split_once('.')
                        .map_or(name.clone(), |(_, rest)| rest.to_string());
                }
                Ok(a) => break a,
                Err(e) => {
                    report
                        .findings
                        .push(Finding::fail("WHOIS", format!("{e:#}")));
                    return;
                }
            }
        };
        let s = whois::summarize(&answer.text);
        let mut row = |k: &str, v: String| report.rows.push(vec![k.to_string(), v]);
        row("Queried", answer.servers.join(" → "));
        if name != target {
            row("Looked up", name.clone());
        }
        let expires = s
            .expires
            .as_deref()
            .and_then(|e| whois::parse_day(e).map(|d| (e, d - whois::today())));
        for (label, value) in [
            ("Registrar", s.registrar.clone()),
            ("Created", s.created.clone()),
            ("Updated", s.updated.clone()),
            ("Range", s.range.clone()),
            ("Network", s.net_name.clone()),
            ("Organisation", s.org.clone()),
            ("Country", s.country.clone()),
            ("DNSSEC", s.dnssec.clone()),
        ] {
            if let Some(v) = value {
                row(label, v);
            }
        }
        if let Some((raw, days)) = expires {
            row("Expires", format!("{raw} ({days} days)"));
        } else if let Some(raw) = &s.expires {
            row("Expires", raw.clone());
        }
        if !s.status.is_empty() {
            row("Status", s.status.join(", "));
        }
        if !s.nameservers.is_empty() {
            row("Name servers", s.nameservers.join(", "));
        }
        if report.rows.len() <= 2 {
            // Nothing recognisable (privacy-redacted or an unusual format): show the text.
            for (k, v) in whois::fields(&answer.text).into_iter().take(30) {
                report.rows.push(vec![k, v]);
            }
        }
        if is_ip {
            report.findings.push(Finding::ok(
                "WHOIS",
                format!(
                    "Allocation record from {}.",
                    answer.servers.last().map_or("", String::as_str)
                ),
            ));
            return;
        }
        if whois::is_no_match(&answer.text) {
            report.findings.push(Finding::info(
                "Registration",
                format!("{name} appears to be unregistered."),
            ));
            return;
        }
        report.findings.push(Finding::ok(
            "WHOIS",
            format!(
                "Record from {}.",
                answer.servers.last().map_or("", String::as_str)
            ),
        ));
        match expires {
            Some((_, days)) if days < 0 => report.findings.push(Finding::fail(
                "Expiry",
                format!("Expired {} days ago.", -days),
            )),
            Some((_, days)) if days < 30 => report
                .findings
                .push(Finding::warn("Expiry", format!("Expires in {days} days."))),
            Some((_, days)) => report
                .findings
                .push(Finding::ok("Expiry", format!("Expires in {days} days."))),
            None => report.findings.push(Finding::info(
                "Expiry",
                "No expiry date published (common for some country TLDs).",
            )),
        }
        let has = |needle: &str| {
            s.status
                .iter()
                .any(|st| st.to_ascii_lowercase().contains(needle))
        };
        if has("pendingdelete") || has("redemption") {
            report.findings.push(Finding::fail(
                "Status",
                "The domain is being deleted or is in its redemption period.",
            ));
        } else if has("hold") {
            report.findings.push(Finding::fail(
                "Status",
                "The domain is on hold, so it won't resolve.",
            ));
        } else if has("transferprohibited") {
            report.findings.push(Finding::ok(
                "Transfer lock",
                "A registrar/registry transfer lock is set.",
            ));
        } else if !s.status.is_empty() {
            report.findings.push(Finding::info(
                "Transfer lock",
                "No transfer lock in the status.",
            ));
        }
    }

    /// The addresses to connect to for `host`, IPv4 first, or a failure finding.
    async fn web_addresses(&self, report: &mut Report, host: &str) -> Option<Vec<IpAddr>> {
        let mut ips = self.addresses(host).await;
        ips.sort_by_key(|ip| ip.is_ipv6());
        if ips.is_empty() {
            report.findings.push(Finding::fail(
                "DNS lookup",
                format!("{host} does not resolve to an address."),
            ));
            None
        } else {
            Some(ips)
        }
    }

    async fn http(&self, report: &mut Report) {
        let host = report.query.target.clone();
        report.columns = vec!["Start", "Step", "Status", "Time", "Notes"];
        let Some(ips) = self.web_addresses(report, &host).await else {
            return;
        };
        for https in [false, true] {
            let scheme = if https { "https" } else { "http" };
            let mut url = web::Url::root(https, &host);
            let mut ip = ips[0];
            let mut seen = vec![url.display()];
            let mut last: Option<web::Response> = None;
            for hop in 0..=MAX_REDIRECTS {
                let response = match web::fetch(&url, ip, self.timeout).await {
                    Ok(r) => r,
                    Err(e) => {
                        report.rows.push(vec![
                            scheme.into(),
                            url.display(),
                            "-".into(),
                            "-".into(),
                            shorten(&format!("{e:#}"), 90),
                        ]);
                        let finding = if https || hop > 0 {
                            Finding::fail("Connection", format!("{}: {e:#}", url.display()))
                        } else {
                            Finding::warn("HTTP", format!("http:// is not reachable: {e:#}"))
                        };
                        report.findings.push(finding);
                        break;
                    }
                };
                let head = &response.head;
                let location = head
                    .header("location")
                    .filter(|_| (300..400).contains(&head.status));
                let mut notes = Vec::new();
                if let Some(l) = location {
                    notes.push(format!("→ {l}"));
                } else if let Some(s) = head.header("server") {
                    notes.push(s.to_string());
                }
                if response.trust_error.is_some() {
                    notes.push("untrusted certificate".into());
                }
                report.rows.push(vec![
                    if hop == 0 {
                        scheme.into()
                    } else {
                        String::new()
                    },
                    url.display(),
                    format!("{} {}", head.status, head.reason)
                        .trim()
                        .to_string(),
                    format!("{} ms", response.ms),
                    notes.join("; "),
                ]);
                if let Some(err) = &response.trust_error {
                    // One finding per host, however many hops or schemes see it.
                    let prefix = format!("{}: ", url.host);
                    if !report
                        .findings
                        .iter()
                        .any(|f| f.title == "Certificate" && f.detail.starts_with(&prefix))
                    {
                        report
                            .findings
                            .push(Finding::fail("Certificate", format!("{prefix}{err}")));
                    }
                }
                let next = location.and_then(|l| url.join(l));
                let Some(next) = next else {
                    last = Some(response);
                    break;
                };
                if seen.contains(&next.display()) {
                    report.findings.push(Finding::fail(
                        "Redirects",
                        format!("{scheme}:// redirects in a loop at {}.", next.display()),
                    ));
                    break;
                }
                if hop == MAX_REDIRECTS {
                    report.findings.push(Finding::warn(
                        "Redirects",
                        format!("{scheme}:// still redirecting after {MAX_REDIRECTS} hops."),
                    ));
                    break;
                }
                // Resolve the next host; never follow a redirect onto a private
                // network from a public name.
                let next_ips = if next.host == url.host {
                    vec![ip]
                } else {
                    self.addresses(&next.host).await
                };
                let Some(&next_ip) = next_ips.first() else {
                    report.findings.push(Finding::fail(
                        "Redirects",
                        format!("{} does not resolve.", next.host),
                    ));
                    break;
                };
                if is_internal(next_ip) && !is_internal(ips[0]) {
                    report.findings.push(Finding::warn(
                        "Redirects",
                        format!("Redirect to internal address {next_ip} was not followed."),
                    ));
                    break;
                }
                seen.push(next.display());
                (url, ip) = (next, next_ip);
                last = Some(response);
            }
            let Some(response) = last else { continue };
            let status = response.head.status;
            let chain = seen.len() - 1;
            if https || !url.https {
                // The end of this scheme's chain.
                let verdict = match status {
                    200..=299 => Finding::ok(
                        format!("{scheme} status"),
                        format!("{} answered {status}.", url.display()),
                    ),
                    300..=399 => Finding::warn(
                        format!("{scheme} status"),
                        format!(
                            "{} answered {status} with no usable Location.",
                            url.display()
                        ),
                    ),
                    400..=499 => Finding::warn(
                        format!("{scheme} status"),
                        format!(
                            "{} answered {status} {}.",
                            url.display(),
                            response.head.reason
                        ),
                    ),
                    _ => Finding::fail(
                        format!("{scheme} status"),
                        format!(
                            "{} answered {status} {}.",
                            url.display(),
                            response.head.reason
                        ),
                    ),
                };
                report.findings.push(verdict);
            }
            if !https {
                report.findings.push(if url.https {
                    Finding::ok("HTTP → HTTPS", format!("http:// redirects to https:// ({chain} hop(s))."))
                } else {
                    Finding::warn("HTTP → HTTPS", "http:// does not redirect to https://, so visitors can stay on an unencrypted connection.")
                });
            } else if url.https {
                match response
                    .head
                    .header("strict-transport-security")
                    .map(|h| (h, web::hsts_max_age(h)))
                {
                    Some((h, Some(age))) if age >= HSTS_MIN => {
                        report.findings.push(Finding::ok("HSTS", h.to_string()))
                    }
                    Some((h, Some(age))) => report.findings.push(Finding::warn(
                        "HSTS",
                        format!("max-age={age} is under six months: {h}"),
                    )),
                    Some((h, None)) => report
                        .findings
                        .push(Finding::warn("HSTS", format!("No max-age in: {h}"))),
                    None => report.findings.push(Finding::warn(
                        "HSTS",
                        "No Strict-Transport-Security header.",
                    )),
                }
                if chain > 3 {
                    report.findings.push(Finding::warn(
                        "Redirects",
                        format!("{chain} redirects before the final page."),
                    ));
                }
            }
        }
    }

    async fn cert(&self, report: &mut Report) {
        let host = report.query.target.clone();
        report.columns = vec!["#", "Subject", "Issuer", "Expires", "Key"];
        let Some(ips) = self.web_addresses(report, &host).await else {
            return;
        };
        let mut failure = None;
        let mut found = None;
        // Try the first couple of addresses: one may be dead.
        for ip in ips.iter().take(2) {
            match web::tls_probe(&host, *ip, 443, self.timeout).await {
                Ok(p) => {
                    found = Some((p, *ip));
                    break;
                }
                Err(e) => failure = Some(format!("{ip}: {e:#}")),
            }
        }
        let Some((probe, ip)) = found else {
            report
                .findings
                .push(Finding::fail("TLS", failure.unwrap_or_default()));
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        for (i, c) in probe.chain.iter().enumerate() {
            report.rows.push(vec![
                (i + 1).to_string(),
                c.subject.clone(),
                c.issuer.clone(),
                fmt::date(c.not_after),
                c.key.clone(),
            ]);
        }
        let leaf = &probe.chain[0];
        report.findings.push(Finding::ok(
            "TLS",
            format!(
                "{} on {ip}:443, handshake in {} ms.",
                probe.protocol, probe.connect_ms
            ),
        ));
        match &probe.trust_error {
            None => report.findings.push(Finding::ok(
                "Trust",
                "The chain is trusted by the Mozilla root store.",
            )),
            Some(e) => report.findings.push(Finding::fail("Trust", e.clone())),
        }
        if leaf.names.is_empty() {
            report.findings.push(Finding::fail(
                "Hostname",
                "The certificate has no subject alternative names.",
            ));
        } else if web::covers(&leaf.names, &host) {
            report.findings.push(Finding::ok(
                "Hostname",
                format!("{host} is covered by the certificate."),
            ));
        } else {
            report.findings.push(Finding::fail(
                "Hostname",
                format!("{host} is not covered by: {}", leaf.names.join(", ")),
            ));
        }
        let days = (leaf.not_after - now).div_euclid(86_400);
        let (from, until) = (fmt::date(leaf.not_before), fmt::date(leaf.not_after));
        report.findings.push(if now < leaf.not_before {
            Finding::fail("Validity", format!("Not valid until {from}."))
        } else if days < 0 {
            Finding::fail(
                "Validity",
                format!("Expired on {until} ({} days ago).", -days),
            )
        } else if days < 14 {
            Finding::fail("Validity", format!("Expires on {until}, in {days} days."))
        } else if days < 30 {
            Finding::warn("Validity", format!("Expires on {until}, in {days} days."))
        } else {
            Finding::ok(
                "Validity",
                format!("Valid {from} to {until}; expires in {days} days."),
            )
        });
        let weak_rsa = leaf
            .key
            .strip_prefix("RSA ")
            .and_then(|b| b.parse::<u32>().ok())
            .is_some_and(|b| b < 2048);
        report.findings.push(if weak_rsa {
            Finding::fail(
                "Key",
                format!("{} bits is too short; use 2048 or more.", leaf.key),
            )
        } else {
            Finding::ok("Key", format!("{} bit key.", leaf.key))
        });
        if probe.protocol == "TLS 1.2" || probe.protocol == "TLS 1.3" {
            report.findings.push(Finding::ok(
                "Protocol",
                format!("{} negotiated.", probe.protocol),
            ));
        } else {
            report.findings.push(Finding::warn(
                "Protocol",
                format!("{} negotiated.", probe.protocol),
            ));
        }
        if probe.chain.len() == 1 && !leaf.self_signed && probe.trust_error.is_some() {
            report.findings.push(Finding::warn("Chain", "Only the leaf was sent; a missing intermediate certificate is a common cause of trust errors."));
        }
        report
            .findings
            .push(Finding::info("Names", leaf.names.join(", ")));
    }

    async fn smtp(&self, report: &mut Report) {
        let target = report.query.target.clone();
        report.columns = vec!["Host", "Address", "Connect", "Banner", "STARTTLS"];
        // An IP is probed directly; a name is probed via its MX hosts, or itself.
        let hosts: Vec<String> = if target.parse::<IpAddr>().is_ok() {
            vec![target.clone()]
        } else {
            let mut mx: Vec<(u16, String)> = self
                .lookup(&target, RecordType::MX)
                .await
                .records()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::MX(m) => Some((m.preference, trim_dot(&m.exchange))),
                    _ => None,
                })
                .filter(|(_, h)| !h.is_empty())
                .collect();
            mx.sort();
            if mx.is_empty() {
                vec![target.clone()]
            } else {
                mx.into_iter().map(|(_, h)| h).collect()
            }
        };
        let futures = hosts.iter().map(|host| async move {
            let ips = self.addresses(host).await;
            // Prefer IPv4: many networks have no working IPv6 path.
            let ip = ips.iter().find(|i| i.is_ipv4()).or(ips.first()).copied();
            let result = match ip {
                Some(ip) => {
                    Some(smtp::probe(SocketAddr::new(ip, 25), self.timeout, "dnstui.invalid").await)
                }
                None => None,
            };
            (host.clone(), ip, result)
        });
        let probes = bounded(futures.collect(), 4).await;
        for (host, ip, result) in probes {
            let addr = ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into());
            match result {
                None => {
                    report
                        .rows
                        .push(vec![host.clone(), addr, "-".into(), "-".into(), "-".into()]);
                    report.findings.push(Finding::fail(
                        "SMTP",
                        format!("{host} does not resolve to an address."),
                    ));
                }
                Some(Err(e)) => {
                    report
                        .rows
                        .push(vec![host.clone(), addr, "-".into(), "-".into(), "-".into()]);
                    report.findings.push(Finding::fail(
                        "SMTP",
                        format!("{host}: {e:#}. Many ISPs block outbound port 25."),
                    ));
                }
                Some(Ok(p)) => {
                    report.rows.push(vec![
                        host.clone(),
                        addr,
                        format!("{} ms", p.connect_ms),
                        shorten(&p.banner, 60),
                        if p.starttls {
                            "yes".into()
                        } else {
                            "no".into()
                        },
                    ]);
                    report.findings.push(Finding::ok(
                        "SMTP",
                        format!("{host} answered in {} ms.", p.connect_ms),
                    ));
                    report.findings.push(if p.starttls {
                        Finding::ok("STARTTLS", format!("{host} offers STARTTLS."))
                    } else {
                        Finding::warn(
                            "STARTTLS",
                            format!(
                                "{host} does not offer STARTTLS; mail to it travels unencrypted."
                            ),
                        )
                    });
                }
            }
        }
    }
}

/// Run futures with at most `limit` in flight, results in input order. The
/// futures are collected first so they don't capture a borrowing closure,
/// which would stop the task being `Send` for any lifetime.
async fn bounded<F: Future>(futures: Vec<F>, limit: usize) -> Vec<F::Output> {
    stream::iter(futures).buffered(limit).collect().await
}

/// The system's name servers, each reachable over UDP *and* TCP. A resolv.conf
/// server is otherwise UDP-only, and a large answer (a long SPF or TXT set)
/// comes back truncated with nothing to retry it over.
fn with_tcp_fallback(servers: Vec<NameServerConfig>) -> Vec<NameServerConfig> {
    servers
        .into_iter()
        .map(|s| NameServerConfig::udp_and_tcp(s.ip))
        .collect()
}

/// Loopback, private, link-local and similar addresses.
fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn join_ips(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A record's data as one display string.
fn rdata_text(data: &RData) -> String {
    match data {
        RData::TXT(t) => txt_text(&t.txt_data),
        RData::CNAME(c) => trim_dot(&c.0),
        RData::A(a) => a.0.to_string(),
        RData::AAAA(a) => a.0.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_servers_get_a_tcp_fallback() {
        let udp_only = vec![NameServerConfig::udp("192.0.2.53".parse().unwrap())];
        assert_eq!(udp_only[0].connections.len(), 1);
        let fixed = with_tcp_fallback(udp_only);
        assert_eq!(fixed[0].ip, "192.0.2.53".parse::<IpAddr>().unwrap());
        assert_eq!(fixed[0].connections.len(), 2);
    }

    #[test]
    fn internal_addresses() {
        for a in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(is_internal(a.parse().unwrap()), "{a}");
        }
        for a in ["8.8.8.8", "1.1.1.1", "2606:4700::1111"] {
            assert!(!is_internal(a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn fqdn_always_ends_with_one_dot() {
        assert_eq!(fqdn("example.com"), "example.com.");
        assert_eq!(fqdn("example.com."), "example.com.");
    }

    #[test]
    fn shorten_counts_characters() {
        assert_eq!(shorten("abcdef", 4), "abc…");
        assert_eq!(shorten("abc", 4), "abc");
        assert_eq!(shorten("ééééé", 3), "éé…");
    }

    #[test]
    fn txt_strings_are_concatenated() {
        let parts: Vec<Box<[u8]>> = vec![b"v=DKIM1; p=AB".to_vec().into(), b"CD".to_vec().into()];
        assert_eq!(txt_text(&parts), "v=DKIM1; p=ABCD");
    }
}

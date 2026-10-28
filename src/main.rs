mod app;
mod config;
mod dnsbl;
mod email;
mod engine;
mod fmt;
mod query;
mod report;
mod smtp;
mod text;
mod theme;
mod tui;
mod ui;
mod web;
mod whois;

use std::{net::IpAddr, path::PathBuf, process::ExitCode};

use clap::{Args, Parser, Subcommand};
use color_eyre::eyre::{Result, WrapErr, eyre};

use query::Check;
use report::Severity;

/// MXToolbox-style DNS, e-mail and blocklist checks in the terminal.
///
/// With no subcommand this opens the terminal UI. A subcommand runs one check
/// and prints the result exactly as the UI shows it, e.g. `dnstui whois
/// example.com`.
#[derive(Parser, Debug)]
#[command(version, about, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Query to run on startup, e.g. `mx:example.com` or `example.com`.
    query: Option<String>,

    /// Print the result of QUERY and exit instead of opening the terminal UI.
    #[arg(short, long, requires = "query")]
    print: bool,

    #[command(flatten)]
    common: Common,

    /// Print the available themes and exit.
    #[arg(long)]
    list_themes: bool,

    /// Print the available checks and exit.
    #[arg(long)]
    list_checks: bool,
}

/// Options that work with the UI and with every subcommand.
#[derive(Args, Debug)]
struct Common {
    /// DNS server to ask [default: `dns_server` from the config, else the
    /// system's resolvers].
    #[arg(short, long, value_name = "IP", global = true)]
    server: Option<IpAddr>,

    /// Config file to use [default: ~/.config/dnstui/config.yml].
    #[arg(short, long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    /// Use this theme instead of the one in the config for this run.
    #[arg(long, value_name = "NAME", global = true)]
    theme: Option<String>,

    /// Never colour printed output (also off when piped or NO_COLOR is set).
    #[arg(long, global = true)]
    no_color: bool,
}

/// What to look up.
#[derive(Args, Debug)]
struct Target {
    /// A domain name or IP address (a URL or user@host is cleaned up).
    target: String,
}

#[derive(Args, Debug)]
struct DkimTarget {
    /// The domain whose DKIM key to look up.
    target: String,
    /// The selector (the `s=` of a DKIM-Signature header) [default: try common ones].
    selector: Option<String>,
}

/// One subcommand per check; the names are the `prefix:` of the UI's queries.
#[derive(Subcommand, Debug)]
enum Command {
    /// Mail servers, their addresses and redundancy.
    Mx(Target),
    /// IPv4 addresses.
    A(Target),
    /// IPv6 addresses.
    Aaaa(Target),
    /// All TXT records.
    Txt(Target),
    /// Authoritative name servers.
    Ns(Target),
    /// Canonical name of an alias.
    Cname(Target),
    /// Zone start of authority.
    Soa(Target),
    /// Reverse DNS of an IP (or of a host's addresses).
    #[command(alias = "rdns")]
    Ptr(Target),
    /// Certificate authorities allowed to issue.
    Caa(Target),
    /// SPF record, syntax and the 10-lookup limit.
    Spf(Target),
    /// DMARC policy.
    Dmarc(Target),
    /// DKIM key for a selector.
    Dkim(DkimTarget),
    /// DNS blocklists for an IP (or a host's addresses).
    #[command(alias = "dnsbl")]
    Blacklist(Target),
    /// Port 25 banner and STARTTLS of the mail servers.
    Smtp(Target),
    /// Registrar, dates, status and name servers.
    Whois(Target),
    /// http:// and https:// responses, redirects and HSTS.
    #[command(alias = "https")]
    Http(Target),
    /// TLS certificate chain, hostname and expiry.
    #[command(alias = "tls", alias = "ssl")]
    Cert(Target),
}

impl Command {
    /// The same `check:target[:selector]` text the UI takes, so both paths
    /// share one parser and its validation.
    fn query_text(&self) -> String {
        let (check, target) = match self {
            Command::Mx(t) => (Check::Mx, &t.target),
            Command::A(t) => (Check::A, &t.target),
            Command::Aaaa(t) => (Check::Aaaa, &t.target),
            Command::Txt(t) => (Check::Txt, &t.target),
            Command::Ns(t) => (Check::Ns, &t.target),
            Command::Cname(t) => (Check::Cname, &t.target),
            Command::Soa(t) => (Check::Soa, &t.target),
            Command::Ptr(t) => (Check::Ptr, &t.target),
            Command::Caa(t) => (Check::Caa, &t.target),
            Command::Spf(t) => (Check::Spf, &t.target),
            Command::Dmarc(t) => (Check::Dmarc, &t.target),
            Command::Dkim(d) => {
                return match &d.selector {
                    Some(s) => format!("dkim:{}:{s}", d.target),
                    None => format!("dkim:{}", d.target),
                };
            }
            Command::Blacklist(t) => (Check::Blacklist, &t.target),
            Command::Smtp(t) => (Check::Smtp, &t.target),
            Command::Whois(t) => (Check::Whois, &t.target),
            Command::Http(t) => (Check::Http, &t.target),
            Command::Cert(t) => (Check::Cert, &t.target),
        };
        format!("{}:{target}", check.prefix())
    }
}

fn exit_for(worst: Severity) -> ExitCode {
    match worst {
        Severity::Ok | Severity::Info => ExitCode::SUCCESS,
        Severity::Warn => ExitCode::from(1),
        Severity::Fail => ExitCode::from(2),
    }
}

/// How wide printed output is: the terminal, else `$COLUMNS`, else 100.
fn output_width(tty: bool) -> usize {
    let from_env = || std::env::var("COLUMNS").ok().and_then(|c| c.parse().ok());
    let width = if tty {
        crossterm::terminal::size()
            .ok()
            .map(|(w, _)| usize::from(w))
    } else {
        None
    };
    width.or_else(from_env).unwrap_or(100).max(40)
}

/// Print a report the way the UI shows it. A closed pipe (`| head`) just ends
/// the output.
fn print_report(report: &report::Report, theme: &theme::Theme, no_color: bool) {
    use std::io::{IsTerminal, Write};
    let tty = std::io::stdout().is_terminal();
    let color = tty && !no_color && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let text = text::render(report, theme, output_width(tty), color);
    let _ = std::io::stdout().write_all(text.as_bytes());
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    color_eyre::install()?;
    let cli = Cli::parse();

    if cli.list_checks {
        for c in Check::ALL {
            println!("{:<10} {}", c.prefix(), c.hint());
        }
        return Ok(ExitCode::SUCCESS);
    }

    let config_path = match &cli.common.config {
        Some(p) => p.clone(),
        None => config::default_path()?,
    };
    let cfg = config::load(&config_path)?;
    let themes_dir = config_path
        .parent()
        .map(|p| p.join("themes"))
        .unwrap_or_else(|| PathBuf::from("themes"));
    let themes = theme::load_themes(&themes_dir, &cfg.themes)?;

    if cli.list_themes {
        for t in &themes {
            println!("{}", t.name);
        }
        return Ok(ExitCode::SUCCESS);
    }

    let theme_name = cli
        .common
        .theme
        .clone()
        .unwrap_or_else(|| cfg.theme.clone());
    let Some(theme) = theme::find(&themes, &theme_name).cloned() else {
        return Err(eyre!(
            "unknown theme '{theme_name}' (see --list-themes, or define it under `themes:` in {})",
            config_path.display()
        ));
    };
    let default_check = Check::parse(&cfg.default_check).ok_or_else(|| {
        eyre!(
            "invalid default_check '{}' in {}",
            cfg.default_check,
            config_path.display()
        )
    })?;
    let engine = engine::Engine::new(&cfg, cli.common.server)?;

    // `dnstui whois example.com` and `dnstui -p whois:example.com`.
    let printed = match (&cli.command, cli.print) {
        (Some(command), _) => Some(command.query_text()),
        (None, true) => Some(cli.query.clone().unwrap_or_default()),
        (None, false) => None,
    };
    if let Some(text) = printed {
        let q = match query::parse(&text, default_check) {
            Ok(q) => q,
            Err(e) => {
                eprintln!("dnstui: {e}");
                return Ok(ExitCode::from(3));
            }
        };
        let report = engine.run(q).await;
        // The terminal background is the user's own; only the colours matter here.
        print_report(&report, &theme.transparent(true), cli.common.no_color);
        return Ok(exit_for(report.worst()));
    }

    {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            eprintln!(
                "dnstui: the terminal UI needs a terminal. To print a result, use e.g. `dnstui mx example.com`."
            );
            return Ok(ExitCode::from(3));
        }
    }
    let terminal = tui::init_terminal()?;
    let result = tui::run(
        terminal,
        engine,
        tui::Settings {
            config_path,
            themes,
            theme_name,
            transparent: cfg.transparent_background,
            default_check,
            initial: cli.query,
        },
    )
    .await;
    tui::restore_terminal();
    result.wrap_err("the terminal UI failed")?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(args: &[&str]) -> String {
        let cli =
            Cli::try_parse_from(std::iter::once("dnstui").chain(args.iter().copied())).unwrap();
        cli.command.expect("a subcommand").query_text()
    }

    #[test]
    fn subcommands_map_to_queries() {
        assert_eq!(text(&["whois", "bespohk.com"]), "whois:bespohk.com");
        assert_eq!(text(&["mx", "example.com"]), "mx:example.com");
        assert_eq!(text(&["https", "example.com"]), "http:example.com");
        assert_eq!(text(&["tls", "example.com"]), "cert:example.com");
        assert_eq!(text(&["dnsbl", "192.0.2.1"]), "blacklist:192.0.2.1");
        assert_eq!(
            text(&["dkim", "example.com", "sel1"]),
            "dkim:example.com:sel1"
        );
        assert_eq!(text(&["dkim", "example.com"]), "dkim:example.com");
    }

    #[test]
    fn global_options_work_after_the_subcommand() {
        let cli = Cli::try_parse_from([
            "dnstui",
            "spf",
            "example.com",
            "-s",
            "1.1.1.1",
            "--no-color",
        ])
        .unwrap();
        assert_eq!(cli.common.server, Some("1.1.1.1".parse().unwrap()));
        assert!(cli.common.no_color);
    }

    #[test]
    fn a_bare_query_still_opens_the_ui() {
        let cli = Cli::try_parse_from(["dnstui", "mx:example.com"]).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.query.as_deref(), Some("mx:example.com"));
        let cli = Cli::try_parse_from(["dnstui", "-p", "whois:example.com"]).unwrap();
        assert!(cli.print);
    }

    #[test]
    fn every_check_has_a_subcommand() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        for c in Check::ALL {
            assert!(cmd.find_subcommand(c.prefix()).is_some(), "{}", c.prefix());
        }
    }

    #[test]
    fn bad_targets_are_rejected_by_the_shared_parser() {
        let q = text(&["mx", "exa mple.com"]);
        assert!(query::parse(&q, Check::Mx).is_err());
    }
}

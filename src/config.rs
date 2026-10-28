//! Configuration file (`~/.config/dnstui/config.yml`).
//!
//! Loading is strict on purpose: unknown keys, bad values and unknown themes
//! are startup errors that name the file and the problem, rather than being
//! silently ignored.

use std::{
    collections::BTreeMap,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use color_eyre::eyre::{Result, WrapErr, eyre};
use serde::Deserialize;

use crate::theme::ThemeSpec;

pub const DEFAULT_CONFIG: &str = "\
# dnstui configuration.
# Everything here is optional; delete a line to get its default.

# Colour theme: default, tokyo-night, catppuccin-frappe, catppuccin-macchiato,
# catppuccin-mocha, catppuccin-latte, dracula, one-dark, gruvbox-dark, nord,
# solarized-dark, rose-pine, monokai, github-dark, everforest, kanagawa, or the
# name of a theme defined under `themes:` below.
# Everything except `default` uses 24-bit colour.  Press `T` in the app to
# preview and pick a theme; the choice is saved here.
theme: default

# Paint the theme's own background (false), or leave the terminal's showing
# through (true) so its transparency and blur are kept. Press `T` then `b`
# in the app to toggle; the choice is saved here.
transparent_background: true

# The DNS server to query, e.g. 1.1.1.1 or 8.8.8.8. Default: the system's
# resolvers (/etc/resolv.conf). Note that some blocklists (Spamhaus) refuse
# queries that arrive through big public resolvers; see the README.
# dns_server: 1.1.1.1

# How long to wait for one DNS query or SMTP step, in seconds.
timeout_secs: 5

# The check selected when a query has no `type:` prefix: a, aaaa, mx, txt, ns,
# cname, soa, ptr, caa, spf, dmarc, dkim, blacklist or smtp.
default_check: mx

# DKIM selectors to try, in addition to the common ones, when a dkim query
# names none.
# dkim_selectors: [s2048, mailgun]

# DNS blocklists to query for the `blacklist` check, in addition to the
# built-in list.
# blacklists: [dnsbl.example.org]

# Your own themes. Every colour is optional and inherits from `base`
# (one of the built-in themes, default: `default`). Colours are #rrggbb,
# an ANSI name such as `red`, or a 0-255 index.
#
# themes:
#   my-theme:
#     base: dracula
#     accent: \"#ff79c6\"
#   # Keys: fg muted accent border selection_bg success info warning error special
";

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub theme: String,
    pub transparent_background: bool,
    pub dns_server: Option<IpAddr>,
    pub timeout_secs: u64,
    pub default_check: String,
    pub dkim_selectors: Vec<String>,
    pub blacklists: Vec<String>,
    pub themes: BTreeMap<String, ThemeSpec>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: "default".into(),
            transparent_background: true,
            dns_server: None,
            timeout_secs: 5,
            default_check: "mx".into(),
            dkim_selectors: Vec::new(),
            blacklists: Vec::new(),
            themes: BTreeMap::new(),
        }
    }
}

impl Config {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs.max(1))
    }

    /// Reject values serde accepts but that make no sense.
    fn validate(&self) -> Result<()> {
        if self.timeout_secs > 120 {
            return Err(eyre!("timeout_secs must be at most 120"));
        }
        for zone in &self.blacklists {
            if zone.trim().is_empty() || zone.contains(char::is_whitespace) {
                return Err(eyre!("blacklists: '{zone}' is not a DNS zone"));
            }
        }
        Ok(())
    }
}

/// `$XDG_CONFIG_HOME/dnstui`, which is `~/.config/dnstui` unless you have
/// moved XDG_CONFIG_HOME.
pub fn config_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(v) if Path::new(&v).is_absolute() => PathBuf::from(v),
        _ => dirs::home_dir()
            .ok_or_else(|| eyre!("cannot determine your home directory"))?
            .join(".config"),
    };
    Ok(base.join("dnstui"))
}

pub fn default_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.yml"))
}

/// Parse config text. A file with only comments/whitespace is the defaults.
pub fn parse(text: &str) -> Result<Config> {
    let blank = text
        .lines()
        .all(|l| l.trim().is_empty() || l.trim_start().starts_with('#'));
    let config: Config = if blank {
        Config::default()
    } else {
        serde_yaml_ng::from_str(text)?
    };
    config.validate()?;
    Ok(config)
}

/// Load the config, creating a commented default file if none exists yet.
pub fn load(path: &Path) -> Result<Config> {
    match fs::read_to_string(path) {
        Ok(text) => parse(&text).wrap_err_with(|| format!("invalid config {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Best effort: not being able to write the template isn't fatal.
            let _ = write_atomic(path, DEFAULT_CONFIG);
            Ok(Config::default())
        }
        Err(e) => Err(e).wrap_err_with(|| format!("cannot read config {}", path.display())),
    }
}

/// Write via a temp file + rename so a crash can't leave a half-written
/// config. Follows a symlinked config file (e.g. managed by stow) instead of
/// replacing the link.
pub(crate) fn write_atomic(path: &Path, text: &str) -> Result<()> {
    let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let dir = target
        .parent()
        .ok_or_else(|| eyre!("config path has no parent directory"))?;
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        std::process::id()
    ));
    fs::write(&tmp, text)?;
    if let Err(e) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Read the config for an in-place edit. A file that already fails to parse is
/// reported as such, so a hand-made mistake isn't blamed on the value being
/// saved.
fn read_for_edit(path: &Path) -> Result<String> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DEFAULT_CONFIG.to_string(),
        Err(e) => return Err(e).wrap_err_with(|| format!("cannot read {}", path.display())),
    };
    parse(&text).wrap_err_with(|| {
        format!(
            "{} has an error, so it was not changed (fix it first, e.g. with E)",
            path.display()
        )
    })?;
    Ok(text)
}

/// Set a top-level `key: value` in the file, keeping every other line (and
/// comments) untouched. `value` is raw YAML. The edit is checked to still
/// parse before anything is written.
pub fn set_value(path: &Path, key: &str, value: &str) -> Result<()> {
    let existing = read_for_edit(path)?;
    let updated = replace_key(&existing, key, value);
    parse(&updated).wrap_err_with(|| format!("refusing to write invalid {key}: {value}"))?;
    write_atomic(path, &updated)
}

fn replace_key(text: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key}:");
    let mut replaced = false;
    let mut out: Vec<String> = text
        .lines()
        .map(|line| {
            if !replaced && line.starts_with(&prefix) {
                replaced = true;
                // Keep a trailing comment (and the spacing before it), if any.
                let rest = &line[prefix.len()..];
                match rest.find(" #") {
                    Some(i) => format!("{key}: {value}{}", &rest[rest[..i].trim_end().len()..]),
                    None => format!("{key}: {value}"),
                }
            } else {
                line.to_string()
            }
        })
        .collect();
    if !replaced {
        // A top-level key at column 0 is valid after any preceding block.
        out.push(format!("{key}: {value}"));
    }
    out.join("\n") + "\n"
}

/// Quote a string as a YAML scalar if it needs it.
pub fn yaml_scalar(s: &str) -> String {
    serde_yaml_ng::to_string(s)
        .map(|t| t.trim_end().to_string())
        .unwrap_or_else(|_| format!("{s:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_template_parses_to_defaults() {
        let c = parse(DEFAULT_CONFIG).unwrap();
        assert_eq!(c.theme, "default");
        assert_eq!(c.timeout_secs, 5);
        assert!(c.dns_server.is_none());
    }

    #[test]
    fn unknown_keys_and_bad_values_are_errors() {
        assert!(parse("them: nord\n").is_err());
        assert!(parse("dns_server: not-an-ip\n").is_err());
        assert!(parse("timeout_secs: 999\n").is_err());
        assert!(parse("blacklists: [\"a b\"]\n").is_err());
    }

    #[test]
    fn replace_key_keeps_comments_and_other_lines() {
        let text = "# hi\ntheme: default   # pick one\ntimeout_secs: 5\n";
        assert_eq!(
            replace_key(text, "theme", "nord"),
            "# hi\ntheme: nord   # pick one\ntimeout_secs: 5\n"
        );
        assert!(replace_key(text, "dns_server", "1.1.1.1").ends_with("dns_server: 1.1.1.1\n"));
    }
}

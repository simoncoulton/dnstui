# dnstui

DNS, e-mail authentication, blocklist, WHOIS and TLS lookups in the terminal, built on
[ratatui](https://ratatui.rs) and [hickory-resolver](https://crates.io/crates/hickory-resolver).
Type a domain or IP, pick a check, and get pass / warn / fail findings above the
raw records.

![dnstui demo: MX, SPF, DMARC, certificate, WHOIS and HTTP checks on github.com, stepping back through the results, and the theme picker](docs/demo.gif)

The demo is the real program in [Ghostty](https://ghostty.org) with the
Catppuccin Frappé theme and JetBrains Mono; `docs/demo/record.sh` regenerates it
(see [Recording the demo](#recording-the-demo)).

## Install

Requires Rust 1.89 or newer.

```
cargo install --path .        # installs ~/.cargo/bin/dnstui
```

Linux and macOS are the targets; it is only tested on Linux so far.

## Usage

```
dnstui [OPTIONS] [QUERY]         open the terminal UI, optionally running QUERY
dnstui <CHECK> <TARGET>          run one check and print the result

  -p, --print           with QUERY, print it instead of opening the UI
  -s, --server <IP>     ask this DNS server
  -c, --config <FILE>   use this config file
      --theme <NAME>    use this theme for this run
      --no-color        never colour printed output
      --list-themes     print available themes and exit
      --list-checks     print available checks and exit
```

`-s`, `-c`, `--theme` and `--no-color` work with every subcommand.

### Without the UI

Every check is a subcommand, named like its `prefix:` in the UI:

```
dnstui whois bespohk.com
dnstui spf example.com
dnstui dkim example.com selector1     # selector optional
dnstui blacklist 203.0.113.9 -s 9.9.9.9
dnstui https example.com              # alias of http; tls and ssl alias cert
```

The output is what the UI shows in its results pane, laid out the same way:

```
whois:bespohk.com  (2.1 s via system resolver)

 OK    WHOIS         Record from whois.registrar.amazon.
 OK    Expiry        Expires in 205 days.
 OK    Transfer lock A registrar/registry transfer lock is set.

Field         Value
Registrar     Amazon Registrar, Inc.
Expires       2027-05-21T21:51:18Z (205 days)
...
```

It is coloured with your theme when stdout is a terminal, and plain when piped
or when `NO_COLOR` is set. It is as wide as the terminal (`$COLUMNS`, else 100,
when piped), and long values wrap inside their column. `dnstui -p whois:example.com`
is the same thing in the UI's `check:target` form.

Exit status: `0` ok or info only, `1` warnings, `2` failures, `3` the target
could not be understood. So `dnstui cert example.com || alert` works in a cron job.

`QUERY` in the UI form is `[check:]target`, e.g. `mx:example.com`,
`spf:example.com`, `blacklist:203.0.113.9`. Without a prefix the selected tab
(or `default_check`) is used. URLs, `user@host` addresses and trailing dots are
cleaned up, so you can paste whatever you have.

## Checks

| Prefix | What it does |
| --- | --- |
| `mx` | Mail servers, their addresses, redundancy, null MX |
| `a`, `aaaa`, `txt`, `cname`, `caa` | The records themselves, with TTLs |
| `ns` | Name servers, and whether each resolves; flags a single NS |
| `soa` | Zone start of authority |
| `ptr` | Reverse DNS of an IP (or of a host's addresses), with forward-confirmed rDNS |
| `spf` | Parses the record, checks the `all` policy, `ptr`, duplicate records, and counts DNS lookups through nested `include:` / `redirect=` against the limit of 10 |
| `dmarc` | Policy, `pct`, subdomain policy, report address |
| `dkim` | `dkim:domain:selector`, or tries ~18 common selectors; flags revoked keys, 1024-bit RSA and `t=y` test mode |
| `blacklist` | Queries 15 DNS blocklists for an IP, or a host's IPv4 addresses |
| `smtp` | Connects to port 25 of each MX, reads the banner, sends `EHLO`, reports `STARTTLS` |
| `whois` | Domain or IP: follows IANA → registry → registrar, shows registrar, dates, status, name servers (or range, network, organisation for IPs); warns before expiry. A subdomain falls back to its parent |
| `http` | Fetches `http://` and `https://` (paste a URL, or `http:host`), follows up to 6 redirects, and checks http→https, status, HSTS lifetime, redirect loops and untrusted certificates |
| `cert` | TLS handshake on port 443 (`tls:` and `ssl:` also work): protocol, trust against the Mozilla roots, hostname coverage, expiry (warn at 30 days, fail at 14), key size, the whole chain. An untrusted chain is still shown, with the reason |

Notes:

- Results are never cached, so a re-run sees a zone change straight away.
- **Blocklists:** Spamhaus and some others refuse queries that arrive through big
  public resolvers (they answer `127.255.255.x`). Those show as `refused`, not
  as listed or clean. Set `dns_server` to your own recursive resolver to get a
  real answer.
- **SMTP:** many ISPs and clouds block outbound port 25, which shows as a
  timeout. Only `EHLO` and `QUIT` are ever sent.
- **WHOIS** is plain port 43 text, so parsing is best effort; when nothing
  recognisable is found the raw fields are shown. Referrals are only followed to
  plain host names. Many registries redact registrant details.
- **HTTP** sends only `GET` for the path and reads the response head, never the
  body. A redirect from a public name onto a private or loopback address is not
  followed. A certificate that fails verification is reported as a failure, and
  the request is then repeated without verification so the redirects can still
  be shown.
- **Cert** checks port 443 only, and trusts the bundled Mozilla root list
  (`webpki-roots`), not your system store, so a corporate CA shows as untrusted.
- DKIM key strength is estimated from the length of the published key.

## Keys

| Key | Action |
| --- | --- |
| `/`, `i`, `Enter` | Type a query |
| `Enter` | (in the box) run it; a `check:` prefix overrides the tab |
| `Tab`, `Shift-Tab` | (in the box) choose the check |
| `←` `→`, `h` `l` | Switch check and re-run on the same target |
| `r` | Re-run |
| `p`, `n` | Older / newer result from this session (last 50) |
| `j k`, `PgUp PgDn`, `g G` | Scroll |
| `T` | Theme picker with live preview (saved); `b` inside it toggles a transparent background |
| `E` | Open the config in `$VISUAL` / `$EDITOR` (else `vi`) |
| `?` | Help |
| `q`, `Ctrl-C` | Quit |

Input editing: `←` `→` `Home` `End`, `Backspace`, `Delete`, `Ctrl-U` (clear),
`Ctrl-W` (delete word), and bracketed paste.

## Configuration

`~/.config/dnstui/config.yml` (honours `$XDG_CONFIG_HOME`). A commented template
is created on first run. Unknown keys and invalid values are startup errors that
say what is wrong, rather than being ignored.

```yaml
theme: tokyo-night            # see below
transparent_background: true  # false paints the theme's own background (toggle: T, then b)
dns_server: 1.1.1.1           # default: the system resolvers
timeout_secs: 5               # per DNS query / SMTP step
default_check: mx             # used when a query has no prefix
dkim_selectors: [s2048]       # tried in addition to the common ones
blacklists: [dnsbl.example.org]   # extra blocklist zones
```

`T` inside the app writes `theme` and `transparent_background` back to this file,
changing only those lines; comments and everything else are left alone.

### Themes

Same scheme as [torrentui](https://github.com/simoncoulton/torrentui): `default`
(your terminal's own ANSI colours), `tokyo-night`, `catppuccin-*`, `dracula`,
`one-dark`, `gruvbox-dark`, `nord`, `solarized-dark`, `rose-pine`, `monokai`,
`github-dark`, `everforest` and `kanagawa`. Each built-in is written to
`~/.config/dnstui/themes/<name>.yml` on first run; edit one, or add your own.
A file with `base: <built-in>` only needs the colours that differ. Colour keys:
`bg fg muted accent border selection_bg success info warning error special`
(`success`/`warning`/`error`/`info` colour the OK / WARN / FAIL / INFO badges).

## Recording the demo

`docs/demo/record.sh` records `docs/demo.gif` from the real binary: it opens a
floating Ghostty window under XWayland, types the session in `docs/demo/driver.py`
into a pty, and captures only that window with ffmpeg (`x11grab`). It needs
`ghostty`, `ffmpeg`, Hyprland (`hyprctl`), `xprop` and Python 3, and uses your
own Ghostty font and theme apart from forcing an opaque background. `COLS`,
`ROWS`, `FONT_SIZE`, `FPS` and `OUT` override the defaults. The queries are live
lookups of `github.com`, so the content changes a little between runs.

## Layout

- `query.rs` – the checks, and parsing of `check:target[:selector]`
- `report.rs` – `Report`, `Finding` and `Severity`: a result as plain data
- `engine.rs` – runs a query over DNS and SMTP; yields a `Report`
- `email.rs` – pure SPF / DMARC / DKIM parsing and linting
- `dnsbl.rs` – blocklist zones and reverse-name helpers
- `smtp.rs` – the port-25 probe
- `whois.rs` – WHOIS client, referral following and field extraction
- `web.rs` – the HTTP head client and TLS certificate inspection
- `config.rs` – YAML config, comment-preserving edits
- `theme.rs` – palettes, built-in themes, custom theme resolution
- `app.rs` – state + key handling (pure, unit-tested)
- `ui.rs` – rendering only (tested with ratatui's `TestBackend`)
- `tui.rs` – the event loop
- `text.rs` – prints a report outside the UI, reusing `ui.rs`'s layout
- `main.rs` – command line (subcommands per check) and dispatch

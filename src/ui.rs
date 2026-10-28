//! Pure rendering: `draw(frame, &app)` has no side effects on app state
//! (apart from reporting the scroll limit). Every colour comes from `app.theme`.

use ratatui::{
    Frame,
    layout::{Constraint, Flex, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph},
};

use crate::{
    app::{App, Mode},
    fmt,
    query::Check,
    report::{Report, Severity},
    theme::Theme,
};

pub fn draw(frame: &mut Frame, app: &App) {
    let t = &app.theme;
    // The theme's page colour, or the terminal's own when transparent.
    frame.render_widget(Block::new().style(t.base()), frame.area());

    let [input, tabs, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_input(frame, app, input);
    draw_tabs(frame, app, tabs);
    draw_results(frame, app, body);
    draw_footer(frame, app, footer);

    match app.mode {
        Mode::Normal | Mode::Input => {}
        Mode::Theme => draw_themes(frame, app),
        Mode::Help => draw_help(frame, t),
    }
}

fn severity_color(t: &Theme, s: Severity) -> Color {
    match s {
        Severity::Ok => t.success,
        Severity::Info => t.info,
        Severity::Warn => t.warning,
        Severity::Fail => t.error,
    }
}

fn block<'a>(t: &Theme, title: impl Into<Line<'a>>, focused: bool) -> Block<'a> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if focused { t.accent } else { t.border }))
        .title(title)
}

fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let editing = app.mode == Mode::Input;
    let title = Line::from(vec![
        Span::styled(" dnstui ", Style::new().fg(t.accent).bold()),
        Span::styled(format!("{} ", app.check.hint()), t.muted()),
    ]);
    let prompt = format!("{}:", app.check.prefix());
    let mut spans = vec![Span::styled(
        prompt.clone(),
        Style::new().fg(t.accent).bold(),
    )];
    if app.input.is_empty() && !editing {
        spans.push(Span::styled(" press / to type a domain or IP", t.muted()));
    } else {
        spans.push(Span::raw(format!(" {}", app.input)));
    }
    let inner = block(t, title, editing);
    let inner_area = inner.inner(area);
    frame.render_widget(Paragraph::new(Line::from(spans)).block(inner), area);
    if editing {
        let x = inner_area.x + prompt.chars().count() as u16 + 1 + app.cursor as u16;
        if x < inner_area.right() {
            frame.set_cursor_position(Position::new(x, inner_area.y));
        }
    }
}

/// Which tabs to show so the selected one is visible within `width` columns:
/// the index to start from.
fn tab_start(labels: &[&str], selected: usize, width: usize) -> usize {
    let cost = |i: usize| labels[i].chars().count() + 3;
    let mut start = 0;
    let mut used: usize = (start..=selected).map(cost).sum();
    while used > width.saturating_sub(4) && start < selected {
        used -= cost(start);
        start += 1;
    }
    start
}

fn draw_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let labels: Vec<&str> = Check::ALL.iter().map(|c| c.label()).collect();
    let selected = Check::ALL.iter().position(|c| *c == app.check).unwrap_or(0);
    let start = tab_start(&labels, selected, area.width as usize);
    let mut spans = vec![Span::styled(if start > 0 { "‹ " } else { "  " }, t.muted())];
    // Leave room for the "›" that says there are more tabs to the right.
    let mut used = 2;
    let mut more = false;
    for (i, label) in labels.iter().enumerate().skip(start) {
        let cell = label.chars().count() + 3;
        if used + cell > (area.width as usize).saturating_sub(2) && i > selected {
            more = true;
            break;
        }
        used += cell;
        let style = if i == selected {
            Style::new()
                .fg(t.accent)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            t.muted()
        };
        spans.push(Span::styled(format!(" {label} "), style));
        spans.push(Span::raw(" "));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
    if more && area.width > 0 {
        let right = Rect::new(area.right() - 1, area.y, 1, 1);
        frame.render_widget(Paragraph::new(Span::styled("›", t.muted())), right);
    }
}

/// Lay out `rows` under `columns` as aligned text lines. Cells wrap inside
/// their column rather than being cut off; when the content is too wide the
/// widest columns give up space first, and the last one takes what is left.
fn table_lines(
    t: &Theme,
    columns: &[&str],
    rows: &[Vec<String>],
    width: usize,
) -> Vec<Line<'static>> {
    const GAP: usize = 2;
    const MIN: usize = 6;
    if columns.is_empty() {
        return Vec::new();
    }
    let cell = |row: &[String], c: usize| row.get(c).cloned().unwrap_or_default();
    // Natural width of each column, longest unbroken word counting as its floor.
    let mut widths: Vec<usize> = (0..columns.len())
        .map(|c| {
            rows.iter()
                .map(|r| cell(r, c).chars().count())
                .chain([columns[c].chars().count()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let budget = width
        .saturating_sub(GAP * (columns.len() - 1))
        .max(columns.len() * MIN);
    while widths.iter().sum::<usize>() > budget {
        let (widest, w) = widths
            .iter()
            .enumerate()
            .max_by_key(|(_, w)| **w)
            .map(|(i, w)| (i, *w))
            .unwrap_or((0, 0));
        if w <= MIN {
            break;
        }
        widths[widest] = w - 1;
    }

    let mut lines = Vec::new();
    let last = columns.len() - 1;
    let header: Vec<Span> = columns
        .iter()
        .enumerate()
        .map(|(c, name)| {
            let w = if c == last { 0 } else { widths[c] + GAP };
            Span::styled(
                format!("{:<w$}", fmt::truncate(name, widths[c]), w = w),
                Style::new().fg(t.accent).bold(),
            )
        })
        .collect();
    lines.push(Line::from(header));
    for row in rows {
        let wrapped: Vec<Vec<String>> = (0..columns.len())
            .map(|c| fmt::wrap(&cell(row, c), widths[c]))
            .collect();
        let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);
        for n in 0..height {
            let spans: Vec<Span> = wrapped
                .iter()
                .enumerate()
                .map(|(c, cell_lines)| {
                    let text = cell_lines.get(n).map_or("", String::as_str);
                    let w = if c == last { 0 } else { widths[c] + GAP };
                    Span::raw(format!("{text:<w$}", w = w))
                })
                .collect();
            lines.push(Line::from(spans));
        }
    }
    lines
}

pub fn report_lines(t: &Theme, report: &Report, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if !report.findings.is_empty() {
        let title_w = report
            .findings
            .iter()
            .map(|f| f.title.chars().count())
            .max()
            .unwrap_or(0)
            .min(28);
        let detail_w = width.saturating_sub(title_w + 9).max(16);
        for f in &report.findings {
            let color = severity_color(t, f.severity);
            let wrapped = fmt::wrap(&f.detail, detail_w);
            for (n, piece) in wrapped.into_iter().enumerate() {
                let (badge, title) = if n == 0 {
                    (
                        Span::styled(
                            format!(" {:<4} ", f.severity.word()),
                            Style::new()
                                .fg(color)
                                .add_modifier(Modifier::BOLD | Modifier::REVERSED),
                        ),
                        Span::styled(
                            format!(" {:<w$} ", fmt::truncate(&f.title, title_w), w = title_w),
                            Style::new().bold(),
                        ),
                    )
                } else {
                    (
                        Span::raw("      "),
                        Span::raw(format!(" {:<w$} ", "", w = title_w)),
                    )
                };
                lines.push(Line::from(vec![badge, title, Span::raw(piece)]));
            }
        }
    }
    if !report.rows.is_empty() {
        if !lines.is_empty() {
            lines.push(Line::raw(""));
        }
        lines.extend(table_lines(t, &report.columns, &report.rows, width));
    }
    lines
}

fn welcome_lines(t: &Theme) -> Vec<Line<'static>> {
    let key = |k: &'static str| Span::styled(k, Style::new().fg(t.accent).bold());
    vec![
        Line::raw(""),
        Line::from(vec![Span::raw(
            "  Look up DNS, e-mail and blocklist records, in one place.",
        )]),
        Line::raw(""),
        Line::from(vec![Span::raw(
            "  Type a domain, or prefix it with a check:",
        )]),
        Line::raw(""),
        Line::from(vec![
            Span::raw("    "),
            key("mx:"),
            Span::raw("example.com            mail servers"),
        ]),
        Line::from(vec![
            Span::raw("    "),
            key("spf:"),
            Span::raw("example.com           SPF record and lookup count"),
        ]),
        Line::from(vec![
            Span::raw("    "),
            key("dmarc:"),
            Span::raw("example.com         DMARC policy"),
        ]),
        Line::from(vec![
            Span::raw("    "),
            key("dkim:"),
            Span::raw("example.com:sel      DKIM key for a selector"),
        ]),
        Line::from(vec![
            Span::raw("    "),
            key("blacklist:"),
            Span::raw("203.0.113.9     DNS blocklists"),
        ]),
        Line::from(vec![
            Span::raw("    "),
            key("smtp:"),
            Span::raw("example.com          port 25 banner and STARTTLS"),
        ]),
        Line::from(vec![
            Span::raw("    "),
            key("whois:"),
            Span::raw("example.com         registrar, expiry, status"),
        ]),
        Line::from(vec![
            Span::raw("    "),
            key("http:"),
            Span::raw("example.com          redirects and HSTS (or paste a URL)"),
        ]),
        Line::from(vec![
            Span::raw("    "),
            key("cert:"),
            Span::raw("example.com          TLS certificate chain and expiry"),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::raw("  "),
            key("Tab"),
            Span::raw(" picks a check, "),
            key("Enter"),
            Span::raw(" runs it, "),
            key("?"),
            Span::raw(" shows every key."),
        ]),
    ]
}

fn draw_results(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let mut title = vec![Span::styled(" Results ", Style::new().fg(t.accent).bold())];
    let lines = if let Some(q) = &app.running {
        title.push(Span::styled(format!("— {} ", q.display()), t.muted()));
        vec![
            Line::raw(""),
            Line::styled(
                format!("  Querying {}…", q.display()),
                Style::new().fg(t.warning),
            ),
        ]
    } else if let Some(report) = app.report() {
        let (ok, warn, fail) = report.tally();
        title.push(Span::styled(
            format!("— {} ", report.query.display()),
            Style::new().fg(t.fg),
        ));
        title.push(Span::styled(
            format!("({} via {}) ", fmt::duration(report.elapsed), report.server),
            t.muted(),
        ));
        let mut lines = report_lines(t, report, area.width.saturating_sub(4) as usize);
        if lines.is_empty() {
            lines.push(Line::styled("  Nothing to show.", t.muted()));
        }
        // Summary on the right edge of the border.
        let _ = (ok, warn, fail);
        lines
    } else {
        welcome_lines(t)
    };

    let mut blk = block(t, Line::from(title), false);
    if let Some(report) = app.report().filter(|_| app.running.is_none()) {
        let (ok, warn, fail) = report.tally();
        let mut right = Vec::new();
        if app.history.len() > 1 {
            right.push(Span::styled(
                format!("{}/{} ", app.selected + 1, app.history.len()),
                t.muted(),
            ));
        }
        for (n, label, s) in [
            (fail, "fail", Severity::Fail),
            (warn, "warn", Severity::Warn),
            (ok, "ok", Severity::Ok),
        ] {
            if n > 0 {
                right.push(Span::styled(
                    format!("{n} {label} "),
                    Style::new().fg(severity_color(t, s)),
                ));
            }
        }
        blk = blk.title_top(Line::from(right).right_aligned());
    }
    let inner = blk.inner(area);
    let limit = lines.len().saturating_sub(inner.height as usize);
    app.scroll_limit.set(limit);
    let offset = app.scroll.min(limit) as u16;
    frame.render_widget(Paragraph::new(lines).block(blk).scroll((offset, 0)), area);
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    if let Some((text, is_error)) = app.status() {
        let color = if is_error { t.error } else { t.success };
        frame.render_widget(
            Paragraph::new(Line::styled(format!(" {text}"), Style::new().fg(color))),
            area,
        );
        return;
    }
    let hints: &[(&str, &str)] = match app.mode {
        Mode::Input => &[("Enter", "run"), ("Tab", "check"), ("Esc", "browse")],
        _ => &[
            ("/", "query"),
            ("←→", "check"),
            ("r", "rerun"),
            ("p/n", "history"),
            ("j/k", "scroll"),
            ("T", "theme"),
            ("?", "help"),
            ("q", "quit"),
        ],
    };
    let mut spans = vec![Span::raw(" ")];
    for (k, v) in hints {
        spans.push(Span::styled(*k, Style::new().fg(t.accent).bold()));
        spans.push(Span::styled(format!(" {v}  "), t.muted()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn popup(area: Rect, width: u16, height: u16) -> Rect {
    let [row] = Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center)
        .areas(area);
    let [col] = Layout::horizontal([Constraint::Length(width.min(area.width))])
        .flex(Flex::Center)
        .areas(row);
    col
}

fn draw_themes(frame: &mut Frame, app: &App) {
    let t = &app.theme;
    let area = popup(frame.area(), 44, app.themes.len() as u16 + 4);
    frame.render_widget(Clear, area);
    frame.render_widget(Block::new().style(t.base()), area);
    let items: Vec<ListItem> = app
        .themes
        .iter()
        .map(|th| {
            let mut spans = vec![Span::raw(format!(" {:<22}", th.name))];
            spans.extend(
                th.swatch()
                    .into_iter()
                    .map(|c| Span::styled("██", Style::new().fg(c))),
            );
            ListItem::new(Line::from(spans))
        })
        .collect();
    let title = format!(
        " Theme — background: {} ",
        if app.transparent {
            "transparent"
        } else {
            "theme"
        }
    );
    let list = List::new(items)
        .block(block(t, title, true).title_bottom(Line::styled(
            " Enter save · b background · Esc cancel ",
            t.muted(),
        )))
        .highlight_style(t.selection());
    let mut state = ListState::default().with_selected(Some(app.theme_cursor));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_help(frame: &mut Frame, t: &Theme) {
    let rows: &[(&str, &str)] = &[
        ("/  i  Enter", "type a query"),
        ("Enter", "run it (in the box)"),
        ("Tab  Shift-Tab", "choose the check (in the box)"),
        ("← →  h l", "switch check and re-run on the same target"),
        ("r", "re-run the query on screen"),
        ("p  n", "older / newer result"),
        ("j k  PgUp PgDn", "scroll;  g G jump to top / bottom"),
        ("T", "theme picker (saved)"),
        ("E", "edit the config in $VISUAL / $EDITOR"),
        ("q  Ctrl-C", "quit"),
        ("", ""),
        ("mx:example.com", "a check prefix beats the selected tab"),
        (
            "dkim:example.com:sel",
            "DKIM needs a selector, or tries common ones",
        ),
    ];
    let area = popup(frame.area(), 74, rows.len() as u16 + 4);
    frame.render_widget(Clear, area);
    frame.render_widget(Block::new().style(t.base()), area);
    let lines: Vec<Line> = rows
        .iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(format!(" {k:<22}"), Style::new().fg(t.accent).bold()),
                Span::raw(*v),
            ])
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(
            block(t, " Help ", true).title_bottom(Line::styled(" any key closes ", t.muted())),
        ),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{query::Query, report::Finding, theme};
    use ratatui::{Terminal, backend::TestBackend};

    fn render(app: &App, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        let buf = terminal.backend().buffer();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn sample() -> Report {
        let mut r = Report::new(Query {
            check: Check::Mx,
            target: "example.com".into(),
            selector: None,
        });
        r.server = "1.1.1.1".into();
        r.columns = vec!["Pref", "Mail server", "Addresses", "TTL"];
        r.rows = vec![
            vec![
                "10".into(),
                "mx1.example.com".into(),
                "192.0.2.1".into(),
                "300".into(),
            ],
            vec![
                "20".into(),
                "mx2.example.com".into(),
                "192.0.2.2".into(),
                "300".into(),
            ],
        ];
        r.findings = vec![
            Finding::ok("MX hosts", "Every mail server resolves to an address."),
            Finding::warn("MX redundancy", "Only one mail server."),
        ];
        r
    }

    fn app_with(report: Option<Report>) -> App {
        let mut app = App::new(Check::Mx);
        app.set_themes(theme::builtin_themes(), "default");
        app.mode = Mode::Normal;
        if let Some(r) = report {
            app.history.push(r);
        }
        app
    }

    #[test]
    fn welcome_screen_lists_the_checks() {
        let text = render(&app_with(None), 80, 24);
        assert!(text.contains("press / to type"));
        assert!(text.contains("blacklist:"));
        for check in ["whois:", "http:", "cert:"] {
            assert!(
                text.contains(check),
                "{check} missing from the welcome screen"
            );
        }
    }

    #[test]
    fn report_shows_findings_and_records() {
        let text = render(&app_with(Some(sample())), 90, 24);
        assert!(text.contains("OK"), "{text}");
        assert!(text.contains("WARN"));
        assert!(text.contains("mx2.example.com"));
        assert!(text.contains("mx:example.com"));
        assert!(text.contains("1.1.1.1"));
    }

    #[test]
    fn tiny_terminals_do_not_panic() {
        let app = app_with(Some(sample()));
        for (w, h) in [(1, 1), (10, 3), (20, 6), (30, 12)] {
            render(&app, w, h);
        }
    }

    #[test]
    fn long_values_wrap_instead_of_overflowing() {
        let mut r = sample();
        r.rows = vec![vec![
            "a".into(),
            "v=spf1 ".to_string() + &"include:x.example.com ".repeat(8),
            "x".into(),
            "1".into(),
        ]];
        let text = render(&app_with(Some(r)), 60, 30);
        assert!(text.lines().all(|l| l.chars().count() <= 60));
        assert!(text.matches("include:x.example.com").count() >= 8);
    }

    #[test]
    fn scroll_limit_is_reported() {
        let mut r = sample();
        r.rows = (0..40)
            .map(|i| vec![i.to_string(), "h".into(), "a".into(), "1".into()])
            .collect();
        let app = app_with(Some(r));
        render(&app, 80, 20);
        assert!(app.scroll_limit.get() > 20);
    }

    #[test]
    fn popups_render() {
        let mut app = app_with(None);
        app.mode = Mode::Help;
        assert!(render(&app, 90, 30).contains("Help"));
        app.mode = Mode::Theme;
        assert!(render(&app, 90, 30).contains("tokyo-night"));
    }

    #[test]
    fn tabs_that_do_not_fit_are_marked() {
        let text = render(&app_with(None), 60, 12);
        let tabs = text.lines().nth(3).unwrap_or_default();
        assert!(tabs.trim_end().ends_with('›'), "{tabs:?}");
        // Wide enough for every tab: no marker.
        let wide = render(&app_with(None), 140, 12);
        let tabs = wide.lines().nth(3).unwrap_or_default();
        assert!(tabs.contains("Cert") && !tabs.contains('›'), "{tabs:?}");
    }

    #[test]
    fn selected_tab_stays_visible_on_narrow_terminals() {
        let labels: Vec<&str> = Check::ALL.iter().map(|c| c.label()).collect();
        let start = tab_start(&labels, labels.len() - 1, 40);
        assert!(start > 0);
        let shown: usize = (start..labels.len()).map(|i| labels[i].len() + 3).sum();
        assert!(shown <= 40);
        assert_eq!(tab_start(&labels, 0, 40), 0);
    }
}

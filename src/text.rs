//! Prints a report to a plain terminal or pipe, laid out exactly as the TUI
//! shows it: the same findings badges and aligned, wrapped table.

use ratatui::{
    style::{Color, Modifier, Style},
    text::Line,
};

use crate::{fmt, report::Report, theme::Theme, ui};

/// SGR parameters for a style, or `None` when it adds nothing.
fn sgr(style: Style) -> Option<String> {
    let mut codes: Vec<String> = Vec::new();
    if style.add_modifier.contains(Modifier::BOLD) {
        codes.push("1".into());
    }
    if style.add_modifier.contains(Modifier::REVERSED) {
        codes.push("7".into());
    }
    let fg = match style.fg? {
        Color::Reset => None,
        Color::Black => Some("30".into()),
        Color::Red => Some("31".into()),
        Color::Green => Some("32".into()),
        Color::Yellow => Some("33".into()),
        Color::Blue => Some("34".into()),
        Color::Magenta => Some("35".into()),
        Color::Cyan => Some("36".into()),
        Color::Gray => Some("37".into()),
        Color::DarkGray => Some("90".into()),
        Color::LightRed => Some("91".into()),
        Color::LightGreen => Some("92".into()),
        Color::LightYellow => Some("93".into()),
        Color::LightBlue => Some("94".into()),
        Color::LightMagenta => Some("95".into()),
        Color::LightCyan => Some("96".into()),
        Color::White => Some("97".into()),
        Color::Rgb(r, g, b) => Some(format!("38;2;{r};{g};{b}")),
        Color::Indexed(n) => Some(format!("38;5;{n}")),
    };
    codes.extend(fg);
    (!codes.is_empty()).then(|| codes.join(";"))
}

fn line_text(line: &Line, color: bool) -> String {
    let mut out = String::new();
    for span in &line.spans {
        match color.then(|| sgr(line.style.patch(span.style))).flatten() {
            Some(codes) => out.push_str(&format!("\x1b[{codes}m{}\x1b[0m", span.content)),
            None => out.push_str(&span.content),
        }
    }
    out.trim_end().to_string()
}

/// The report as text, `width` columns wide, with a title line first.
pub fn render(report: &Report, theme: &Theme, width: usize, color: bool) -> String {
    let title = format!(
        "{}  ({} via {})",
        report.query.display(),
        fmt::duration(report.elapsed),
        report.server
    );
    let mut out = String::new();
    out.push_str(&if color {
        format!("\x1b[1m{title}\x1b[0m\n\n")
    } else {
        format!("{title}\n\n")
    });
    let lines = ui::report_lines(theme, report, width.saturating_sub(2));
    if lines.is_empty() {
        out.push_str("Nothing to show.\n");
    }
    for line in &lines {
        out.push_str(&line_text(line, color));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        query::{Check, Query},
        report::Finding,
        theme,
    };

    fn whois_report() -> Report {
        let mut r = Report::new(Query {
            check: Check::Whois,
            target: "example.com".into(),
            selector: None,
        });
        r.server = "system resolver".into();
        r.columns = vec!["Field", "Value"];
        r.rows = vec![
            vec!["Registrar".into(), "Test Registrar Inc.".into()],
            vec!["Expires".into(), "2030-01-01 (1500 days)".into()],
        ];
        r.findings = vec![Finding::ok("Expiry", "Expires in 1500 days.")];
        r
    }

    #[test]
    fn plain_output_has_no_escape_codes_and_matches_the_tui_layout() {
        let text = render(&whois_report(), &theme::default_theme(), 80, false);
        assert!(!text.contains('\x1b'));
        assert!(text.starts_with("whois:example.com  ("));
        assert!(text.contains(" OK    Expiry"), "{text}");
        assert!(text.contains("Field      Value"), "{text}");
        assert!(text.contains("Registrar  Test Registrar Inc."), "{text}");
        assert!(text.lines().all(|l| l.chars().count() <= 80));
    }

    #[test]
    fn colour_output_styles_the_badge() {
        let text = render(&whois_report(), &theme::default_theme(), 80, true);
        assert!(text.contains("\x1b[1;7;32m OK   "), "{text:?}");
        assert!(text.contains("\x1b[0m"));
    }

    #[test]
    fn rgb_themes_use_true_colour() {
        let all = theme::builtin_themes();
        let t = theme::find(&all, "dracula").unwrap();
        let text = render(&whois_report(), t, 80, true);
        assert!(text.contains("38;2;80;250;123"), "{text:?}");
    }

    #[test]
    fn narrow_widths_wrap_instead_of_overflowing() {
        let mut r = whois_report();
        r.rows = vec![vec![
            "Name servers".into(),
            "ns1.example.com, ns2.example.com, ns3.example.com".into(),
        ]];
        let text = render(&r, &theme::default_theme(), 40, false);
        assert!(
            text.lines().skip(2).all(|l| l.chars().count() <= 40),
            "{text}"
        );
        assert!(text.contains("ns3.example.com"));
    }
}

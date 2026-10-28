//! Human-readable formatting helpers.

use std::time::Duration;

pub fn duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.1} s", d.as_secs_f64())
    }
}

/// `YYYY-MM-DD` (UTC) for a Unix timestamp.
pub fn date(unix_secs: i64) -> String {
    // Howard Hinnant's civil_from_days.
    let z = unix_secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Greedy word wrap to `width` columns. Words longer than a line (long TXT
/// values, DKIM keys) are split rather than overflowing. Always returns at
/// least one line.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut len = 0;
    for word in text.split_whitespace() {
        let mut word: Vec<char> = word.chars().collect();
        loop {
            let sep = usize::from(len > 0);
            if len + sep + word.len() <= width {
                if sep == 1 {
                    line.push(' ');
                }
                line.extend(&word);
                len += sep + word.len();
                break;
            }
            if len > 0 {
                lines.push(std::mem::take(&mut line));
                len = 0;
                continue;
            }
            // A word wider than the whole line: break it.
            let rest = word.split_off(width);
            lines.push(word.into_iter().collect());
            word = rest;
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// Truncate to `width` columns with an ellipsis, counting characters.
pub fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else {
        let head: String = text.chars().take(width.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(duration(Duration::from_millis(42)), "42 ms");
        assert_eq!(duration(Duration::from_millis(1500)), "1.5 s");
    }

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_709_251_199), "2024-02-29");
        assert_eq!(date(-86_400), "1969-12-31");
    }

    #[test]
    fn wraps_on_words() {
        assert_eq!(wrap("aaa bbb ccc", 7), ["aaa bbb", "ccc"]);
        assert_eq!(wrap("", 5), [""]);
        assert_eq!(wrap("a  b", 5), ["a b"]);
    }

    #[test]
    fn splits_long_words() {
        assert_eq!(wrap("abcdefgh", 3), ["abc", "def", "gh"]);
        assert_eq!(wrap("x abcdef", 4), ["x", "abcd", "ef"]);
    }

    #[test]
    fn truncates() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 4), "abc");
    }
}

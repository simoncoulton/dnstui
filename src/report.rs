//! The result of a check as plain data: a table of records plus pass/warn/fail
//! findings, like a mail-diagnostics report. No I/O and no rendering here.

use std::time::Duration;

use crate::query::Query;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Severity {
    pub fn word(self) -> &'static str {
        match self {
            Severity::Ok => "OK",
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

impl Finding {
    pub fn new(severity: Severity, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity,
            title: title.into(),
            detail: detail.into(),
        }
    }

    pub fn ok(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(Severity::Ok, title, detail)
    }

    pub fn info(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(Severity::Info, title, detail)
    }

    pub fn warn(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(Severity::Warn, title, detail)
    }

    pub fn fail(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(Severity::Fail, title, detail)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub query: Query,
    pub columns: Vec<&'static str>,
    pub rows: Vec<Vec<String>>,
    pub findings: Vec<Finding>,
    pub elapsed: Duration,
    /// Which resolver answered, for the details line.
    pub server: String,
}

impl Report {
    pub fn new(query: Query) -> Self {
        Self {
            query,
            columns: Vec::new(),
            rows: Vec::new(),
            findings: Vec::new(),
            elapsed: Duration::ZERO,
            server: String::new(),
        }
    }

    /// The worst finding, or `Ok` when there are none.
    pub fn worst(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Ok)
    }

    /// Counts of (ok, warn, fail) findings; `Info` is not counted.
    pub fn tally(&self) -> (usize, usize, usize) {
        let n = |s| self.findings.iter().filter(|f| f.severity == s).count();
        (n(Severity::Ok), n(Severity::Warn), n(Severity::Fail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{Check, Query};

    fn report() -> Report {
        Report::new(Query {
            check: Check::Mx,
            target: "example.com".into(),
            selector: None,
        })
    }

    #[test]
    fn worst_and_tally() {
        let mut r = report();
        assert_eq!(r.worst(), Severity::Ok);
        r.findings.push(Finding::ok("a", ""));
        r.findings.push(Finding::info("b", ""));
        r.findings.push(Finding::warn("c", ""));
        assert_eq!(r.worst(), Severity::Warn);
        r.findings.push(Finding::fail("d", ""));
        assert_eq!(r.worst(), Severity::Fail);
        assert_eq!(r.tally(), (1, 1, 1));
    }
}

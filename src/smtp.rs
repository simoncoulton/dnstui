//! A minimal SMTP probe: connect, read the banner, say EHLO, note what the
//! server offers, and quit. Nothing is ever sent beyond that.

use std::{net::SocketAddr, time::Duration};

use color_eyre::eyre::{Result, WrapErr, bail, eyre};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::{Instant, timeout},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub banner: String,
    pub connect_ms: u128,
    pub starttls: bool,
    pub size: Option<u64>,
    pub capabilities: Vec<String>,
}

/// One SMTP reply: the code and its text lines (without code or separator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

/// Split one reply line into `(code, is_last, text)`.
pub fn parse_line(line: &str) -> Option<(u16, bool, &str)> {
    let line = line.trim_end();
    let code: u16 = line.get(..3)?.parse().ok()?;
    match line.as_bytes().get(3) {
        Some(b'-') => Some((code, false, &line[4..])),
        Some(b' ') => Some((code, true, &line[4..])),
        None => Some((code, true, "")),
        _ => None,
    }
}

async fn read_reply<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Result<Reply> {
    let mut lines = Vec::new();
    loop {
        let mut raw = String::new();
        // A hostile server could stream forever; bound the line and the count.
        if reader.read_line(&mut raw).await? == 0 {
            bail!("connection closed by the server");
        }
        if raw.len() > 2048 || lines.len() > 64 {
            bail!("reply too long");
        }
        let (code, last, text) =
            parse_line(&raw).ok_or_else(|| eyre!("not an SMTP reply: {}", raw.trim()))?;
        lines.push((code, text.to_string()));
        if last {
            let code = lines[0].0;
            return Ok(Reply {
                code,
                lines: lines.into_iter().map(|(_, t)| t).collect(),
            });
        }
    }
}

/// Fold an EHLO reply into capabilities.
pub fn capabilities(reply: &Reply) -> (bool, Option<u64>, Vec<String>) {
    // The first line is the greeting, not a capability.
    let caps: Vec<String> = reply
        .lines
        .iter()
        .skip(1)
        .map(|l| l.to_ascii_uppercase())
        .collect();
    let starttls = caps.iter().any(|c| c == "STARTTLS");
    let size = caps
        .iter()
        .find_map(|c| c.strip_prefix("SIZE "))
        .and_then(|n| n.trim().parse().ok());
    (starttls, size, caps)
}

pub async fn probe(addr: SocketAddr, limit: Duration, ehlo_name: &str) -> Result<Probe> {
    let started = Instant::now();
    let stream = timeout(limit, TcpStream::connect(addr))
        .await
        .map_err(|_| eyre!("timed out connecting to port {}", addr.port()))?
        .wrap_err("cannot connect")?;
    let connect_ms = started.elapsed().as_millis();
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    let banner = timeout(limit, read_reply(&mut reader))
        .await
        .map_err(|_| eyre!("timed out waiting for the banner"))??;
    if banner.code != 220 {
        bail!(
            "unexpected banner: {} {}",
            banner.code,
            banner.lines.join(" ")
        );
    }
    write
        .write_all(format!("EHLO {ehlo_name}\r\n").as_bytes())
        .await?;
    let ehlo = timeout(limit, read_reply(&mut reader))
        .await
        .map_err(|_| eyre!("timed out waiting for the EHLO reply"))??;
    let _ = write.write_all(b"QUIT\r\n").await;
    if ehlo.code != 250 {
        bail!("EHLO refused: {} {}", ehlo.code, ehlo.lines.join(" "));
    }
    let (starttls, size, capabilities) = capabilities(&ehlo);
    Ok(Probe {
        banner: banner.lines.join(" "),
        connect_ms,
        starttls,
        size,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reply_lines() {
        assert_eq!(
            parse_line("250-STARTTLS\r\n"),
            Some((250, false, "STARTTLS"))
        );
        assert_eq!(parse_line("250 OK\r\n"), Some((250, true, "OK")));
        assert_eq!(parse_line("220\r\n"), Some((220, true, "")));
        assert_eq!(parse_line("hello"), None);
        assert_eq!(parse_line("25x ok"), None);
    }

    #[tokio::test]
    async fn reads_multiline_replies() {
        let mut input: &[u8] = b"250-mx.example.com Hello\r\n250-SIZE 35882577\r\n250 STARTTLS\r\n";
        let reply = read_reply(&mut input).await.unwrap();
        assert_eq!(reply.code, 250);
        let (starttls, size, caps) = capabilities(&reply);
        assert!(starttls);
        assert_eq!(size, Some(35882577));
        assert_eq!(caps.len(), 2);
    }

    #[tokio::test]
    async fn closed_connection_is_an_error() {
        let mut input: &[u8] = b"250-partial\r\n";
        assert!(read_reply(&mut input).await.is_err());
    }

    #[tokio::test]
    async fn talks_to_a_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            w.write_all(b"220 test ESMTP\r\n").await.unwrap();
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("EHLO "));
            w.write_all(b"250-test\r\n250 STARTTLS\r\n").await.unwrap();
        });
        let p = probe(addr, Duration::from_secs(2), "dnstui.invalid")
            .await
            .unwrap();
        assert_eq!(p.banner, "test ESMTP");
        assert!(p.starttls);
    }
}

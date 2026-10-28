//! HTTP and TLS probes: a tiny HTTP/1.1 client that reads only the response
//! head, and a TLS handshake that reports the certificate chain whether or not
//! it is trusted.

use std::{net::IpAddr, sync::Arc, time::Duration};

use color_eyre::eyre::{Result, WrapErr, bail, eyre};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, ring},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use x509_parser::{extensions::GeneralName, prelude::*, public_key::PublicKey};

/// The response head is all we read; a server can't make us buffer a body.
const MAX_HEAD: usize = 64 * 1024;

/// Accepts any certificate. Only used to *look at* a chain that failed normal
/// verification (and to send a bodyless `GET /` after that failure is
/// reported); it never makes the result count as trusted.
#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn client_config(roots: RootCertStore, verify: bool) -> Result<Arc<ClientConfig>> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .wrap_err("no usable TLS versions")?;
    let config = if verify {
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(provider())))
            .with_no_client_auth()
    };
    Ok(Arc::new(config))
}

fn webpki_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

pub struct Tls {
    pub stream: TlsStream<TcpStream>,
    /// Why normal verification failed; `None` means the chain is trusted.
    pub trust_error: Option<String>,
    pub connect_ms: u128,
}

async fn handshake(
    host: &str,
    ip: IpAddr,
    port: u16,
    limit: Duration,
    config: Arc<ClientConfig>,
) -> Result<TlsStream<TcpStream>> {
    let tcp = timeout(limit, TcpStream::connect((ip, port)))
        .await
        .map_err(|_| eyre!("timed out connecting to port {port}"))?
        .wrap_err_with(|| format!("cannot connect to port {port}"))?;
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| eyre!("'{host}' is not a valid TLS server name"))?;
    timeout(limit, TlsConnector::from(config).connect(name, tcp))
        .await
        .map_err(|_| eyre!("timed out during the TLS handshake"))?
        .map_err(|e| eyre!("{e}"))
}

/// Connect with verification; if that fails, connect again without it so the
/// chain can still be inspected, remembering why the first attempt failed.
pub async fn connect_tls(host: &str, ip: IpAddr, port: u16, limit: Duration) -> Result<Tls> {
    let started = Instant::now();
    match handshake(host, ip, port, limit, client_config(webpki_roots(), true)?).await {
        Ok(stream) => Ok(Tls {
            stream,
            trust_error: None,
            connect_ms: started.elapsed().as_millis(),
        }),
        Err(first) => {
            let msg = format!("{first:#}");
            // A refused or timed-out connection has no chain to show.
            if msg.starts_with("cannot connect") || msg.starts_with("timed out") {
                return Err(first);
            }
            let stream = handshake(host, ip, port, limit, client_config(webpki_roots(), false)?)
                .await
                .wrap_err_with(|| format!("TLS handshake failed: {msg}"))?;
            Ok(Tls {
                stream,
                trust_error: Some(msg),
                connect_ms: started.elapsed().as_millis(),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub names: Vec<String>,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    /// `RSA 2048`, `EC 256`, ...
    pub key: String,
    pub self_signed: bool,
}

pub fn parse_cert(der: &[u8]) -> Result<CertInfo> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| eyre!("cannot parse certificate: {e}"))?;
    let names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::DNSName(s) => Some(s.to_ascii_lowercase()),
                    GeneralName::IPAddress(b) => match b.len() {
                        4 => Some(IpAddr::from(<[u8; 4]>::try_from(*b).ok()?).to_string()),
                        16 => Some(IpAddr::from(<[u8; 16]>::try_from(*b).ok()?).to_string()),
                        _ => None,
                    },
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let key = match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => format!("RSA {}", rsa.key_size()),
        Ok(PublicKey::EC(ec)) => format!("EC {}", ec.key_size()),
        Ok(PublicKey::DSA(_)) => "DSA".to_string(),
        _ => "unknown".to_string(),
    };
    Ok(CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        names,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        key,
        self_signed: cert.subject() == cert.issuer(),
    })
}

/// Whether a certificate name (possibly `*.example.com`) covers `host`. A
/// wildcard matches exactly one label, as in RFC 6125.
pub fn name_matches(pattern: &str, host: &str) -> bool {
    let (pattern, host) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
    match pattern.strip_prefix("*.") {
        Some(rest) => host
            .split_once('.')
            .is_some_and(|(label, tail)| !label.is_empty() && tail == rest),
        None => pattern == host,
    }
}

pub fn covers(names: &[String], host: &str) -> bool {
    names.iter().any(|n| name_matches(n, host))
}

pub struct TlsProbe {
    pub protocol: String,
    pub chain: Vec<CertInfo>,
    pub trust_error: Option<String>,
    pub connect_ms: u128,
}

pub async fn tls_probe(host: &str, ip: IpAddr, port: u16, limit: Duration) -> Result<TlsProbe> {
    let tls = connect_tls(host, ip, port, limit).await?;
    let (_, conn) = tls.stream.get_ref();
    let protocol = conn.protocol_version().map_or_else(
        || "unknown".to_string(),
        |v| format!("{v:?}").replace("TLSv", "TLS ").replace('_', "."),
    );
    let chain = conn
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|c| parse_cert(c))
        .collect::<Result<Vec<_>>>()?;
    if chain.is_empty() {
        bail!("the server sent no certificate");
    }
    Ok(TlsProbe {
        protocol,
        chain,
        trust_error: tls.trust_error,
        connect_ms: tls.connect_ms,
    })
}

/// Where a request goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn root(https: bool, host: &str) -> Self {
        Self {
            https,
            host: host.to_ascii_lowercase(),
            port: if https { 443 } else { 80 },
            path: "/".into(),
        }
    }

    pub fn parse(text: &str) -> Option<Url> {
        let (https, rest) = if let Some(r) = text.strip_prefix("https://") {
            (true, r)
        } else {
            (false, text.strip_prefix("http://")?)
        };
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
            Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
            None => (rest, "/".to_string()),
        };
        let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let default = if https { 443 } else { 80 };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && !h.ends_with(':') && !h.is_empty() => {
                (h, p.parse().ok()?)
            }
            _ => (authority, default),
        };
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        (!host.is_empty() && !path.contains(['\r', '\n', ' '])).then_some(Url {
            https,
            host,
            port,
            path,
        })
    }

    /// Resolve a `Location:` header against this URL.
    pub fn join(&self, location: &str) -> Option<Url> {
        let loc = location.trim();
        if loc.starts_with("http://") || loc.starts_with("https://") {
            return Url::parse(loc);
        }
        let origin = format!(
            "{}://{}",
            if self.https { "https" } else { "http" },
            self.authority()
        );
        if let Some(rest) = loc.strip_prefix("//") {
            return Url::parse(&format!(
                "{}://{rest}",
                if self.https { "https" } else { "http" }
            ));
        }
        if loc.starts_with('/') {
            return Url::parse(&format!("{origin}{loc}"));
        }
        if loc.is_empty() || loc.contains("://") {
            return None;
        }
        let dir = &self.path[..self.path.rfind('/').map_or(0, |i| i + 1)];
        Url::parse(&format!("{origin}{dir}{loc}"))
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.https { 443 } else { 80 };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub fn display(&self) -> String {
        format!(
            "{}://{}{}",
            if self.https { "https" } else { "http" },
            self.authority(),
            self.path
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    pub reason: String,
    /// Names lower-cased.
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

pub fn parse_head(raw: &[u8]) -> Result<Head> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        bail!(
            "not an HTTP response: {}",
            crate::fmt::truncate(status_line, 40)
        );
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| eyre!("bad status line"))?;
    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Ok(Head {
        status,
        reason: parts.next().unwrap_or("").to_string(),
        headers,
    })
}

async fn read_head<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            // Many servers drop TLS without close_notify once they've answered.
            Err(_) if !buf.is_empty() => break,
            Err(e) => return Err(e.into()),
        }
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            buf.truncate(end);
            return Ok(buf);
        }
        if buf.len() > MAX_HEAD {
            bail!("response headers too large");
        }
    }
    if buf.is_empty() {
        bail!("the server closed the connection without answering");
    }
    Ok(buf)
}

/// The `max-age` of a `Strict-Transport-Security` header, in seconds.
pub fn hsts_max_age(header: &str) -> Option<u64> {
    header.split(';').find_map(|d| {
        let (k, v) = d.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("max-age")
            .then(|| v.trim().trim_matches('"').parse().ok())?
    })
}

pub struct Response {
    pub head: Head,
    pub ms: u128,
    pub trust_error: Option<String>,
}

fn request(url: &Url) -> String {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: dnstui/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.path,
        url.authority(),
        env!("CARGO_PKG_VERSION")
    )
}

/// Send `GET` for `url` to `ip` and read the response head. The body is never
/// read.
pub async fn fetch(url: &Url, ip: IpAddr, limit: Duration) -> Result<Response> {
    let started = Instant::now();
    let exchange = async {
        if url.https {
            let mut tls = connect_tls(&url.host, ip, url.port, limit).await?;
            tls.stream.write_all(request(url).as_bytes()).await?;
            let head = parse_head(&read_head(&mut tls.stream).await?)?;
            Ok::<_, color_eyre::Report>((head, tls.trust_error))
        } else {
            let mut tcp = timeout(limit, TcpStream::connect((ip, url.port)))
                .await
                .map_err(|_| eyre!("timed out connecting to port {}", url.port))?
                .wrap_err_with(|| format!("cannot connect to port {}", url.port))?;
            tcp.write_all(request(url).as_bytes()).await?;
            Ok((parse_head(&read_head(&mut tcp).await?)?, None))
        }
    };
    let (head, trust_error) = timeout(limit * 2, exchange)
        .await
        .map_err(|_| eyre!("timed out waiting for a response"))??;
    Ok(Response {
        head,
        ms: started.elapsed().as_millis(),
        trust_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn wildcards_match_one_label() {
        assert!(name_matches("example.com", "EXAMPLE.com"));
        assert!(name_matches("*.example.com", "www.example.com"));
        assert!(!name_matches("*.example.com", "example.com"));
        assert!(!name_matches("*.example.com", "a.b.example.com"));
        assert!(!name_matches("*.example.com", ".example.com"));
        assert!(covers(
            &["x.org".into(), "*.example.com".into()],
            "api.example.com"
        ));
    }

    #[test]
    fn urls_parse_and_join() {
        let u = Url::parse("https://Example.com:8443/a/b?q=1").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("example.com", 8443, "/a/b?q=1")
        );
        assert_eq!(Url::parse("http://example.com").unwrap().path, "/");
        assert_eq!(Url::parse("http://example.com?x=1").unwrap().path, "/?x=1");
        assert_eq!(
            Url::parse("http://u:p@example.com/").unwrap().host,
            "example.com"
        );
        assert_eq!(Url::parse("http://[::1]:81/").unwrap().host, "::1");
        assert!(Url::parse("ftp://x").is_none());
        assert!(Url::parse("http:///x").is_none());

        let base = Url::parse("http://example.com/a/b").unwrap();
        assert_eq!(
            base.join("https://other.org/x").unwrap().display(),
            "https://other.org/x"
        );
        assert_eq!(
            base.join("/root").unwrap().display(),
            "http://example.com/root"
        );
        assert_eq!(base.join("c").unwrap().display(), "http://example.com/a/c");
        assert_eq!(
            base.join("//cdn.example.net/z").unwrap().display(),
            "http://cdn.example.net/z"
        );
        assert!(base.join("").is_none());
        assert!(base.join("javascript://x").is_none());
    }

    #[test]
    fn hsts_lifetime() {
        assert_eq!(
            hsts_max_age("max-age=63072000; includeSubDomains; preload"),
            Some(63_072_000)
        );
        assert_eq!(hsts_max_age("includeSubDomains; Max-Age=\"10\""), Some(10));
        assert_eq!(hsts_max_age("includeSubDomains"), None);
        assert_eq!(hsts_max_age("max-age=abc"), None);
    }

    #[test]
    fn parses_response_heads() {
        let h = parse_head(b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://x.org/\r\nStrict-Transport-Security: max-age=1\r\n").unwrap();
        assert_eq!((h.status, h.reason.as_str()), (301, "Moved Permanently"));
        assert_eq!(h.header("location"), Some("https://x.org/"));
        assert!(parse_head(b"SSH-2.0-OpenSSH\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 abc\r\n").is_err());
    }

    #[tokio::test]
    async fn fetches_a_head_from_a_plain_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(
                req.starts_with("GET /p HTTP/1.1\r\nHost: localhost:"),
                "{req}"
            );
            sock.write_all(
                b"HTTP/1.1 302 Found\r\nLocation: /next\r\nServer: test\r\n\r\nbody never read",
            )
            .await
            .unwrap();
        });
        let url = Url {
            https: false,
            host: "localhost".into(),
            port,
            path: "/p".into(),
        };
        let r = fetch(&url, "127.0.0.1".parse().unwrap(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(r.head.status, 302);
        assert_eq!(r.head.header("server"), Some("test"));
    }

    #[tokio::test]
    async fn a_silent_server_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            drop(sock);
        });
        let url = Url {
            https: false,
            host: "localhost".into(),
            port,
            path: "/".into(),
        };
        assert!(
            fetch(&url, "127.0.0.1".parse().unwrap(), Duration::from_secs(2))
                .await
                .is_err()
        );
    }

    /// Serve one TLS connection with a fresh self-signed certificate.
    async fn tls_server(names: &[&str]) -> u16 {
        let key = rcgen::KeyPair::generate().unwrap();
        let params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let cert = params.self_signed(&key).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // The verified attempt fails, then the inspecting one succeeds.
            for _ in 0..2 {
                let (sock, _) = listener.accept().await.unwrap();
                if let Ok(mut tls) = acceptor.accept(sock).await {
                    let mut buf = [0u8; 512];
                    if tls.read(&mut buf).await.unwrap_or(0) > 0 {
                        let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=63072000\r\n\r\n").await;
                        let _ = tls.shutdown().await;
                    }
                }
            }
        });
        port
    }

    #[tokio::test]
    async fn untrusted_certificates_are_still_inspected() {
        let port = tls_server(&["localhost", "*.test.example"]).await;
        let probe = tls_probe(
            "localhost",
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(
            probe.trust_error.is_some(),
            "a self-signed cert must not be trusted"
        );
        assert_eq!(probe.chain.len(), 1);
        let leaf = &probe.chain[0];
        assert!(leaf.self_signed);
        assert!(covers(&leaf.names, "localhost") && covers(&leaf.names, "a.test.example"));
        assert!(leaf.not_after > leaf.not_before);
        assert!(probe.protocol.starts_with("TLS 1."), "{}", probe.protocol);
        assert!(leaf.key.starts_with("EC"), "{}", leaf.key);
    }

    #[tokio::test]
    async fn https_fetch_reports_trust_and_headers() {
        let port = tls_server(&["localhost"]).await;
        let url = Url {
            https: true,
            host: "localhost".into(),
            port,
            path: "/".into(),
        };
        let r = fetch(&url, "127.0.0.1".parse().unwrap(), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(r.head.status, 200);
        assert!(r.head.header("strict-transport-security").is_some());
        assert!(r.trust_error.is_some());
    }
}

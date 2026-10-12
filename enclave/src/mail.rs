//! Direct-to-MX email delivery with the MX name taken from the recipient
//! domain's MTA-STS policy (RFC 8461) and verified over STARTTLS (RFC 3207).

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use lettre::address::Envelope;
use lettre::message::dkim::{
    dkim_sign, DkimCanonicalization, DkimCanonicalizationType, DkimConfig, DkimSigningAlgorithm,
    DkimSigningKey,
};
use lettre::message::header::HeaderName;
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::client::{CertificateStore, Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::Deserialize;

const POLICY_MAX_BYTES: usize = 64 * 1024;
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);
const MX_RECORD_TYPE: u16 = 15;
const CODE_MAIL_HTML: &str = include_str!("code_mail.html");

/// An MTA-STS policy (RFC 8461 section 3.2) reduced to the `mx` patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub mx: Vec<String>,
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Parses an MTA-STS policy file (RFC 8461 section 3.2). `mode` may be
/// `enforce` or `testing`; unknown keys are ignored and the first instance of
/// a non-repeated key wins.
pub fn parse_policy(text: &str) -> Result<Policy> {
    let mut version = None;
    let mut mode = None;
    let mut max_age = None;
    let mut mx = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "version" if version.is_none() => version = Some(value),
            "mode" if mode.is_none() => mode = Some(value),
            "max_age" if max_age.is_none() => max_age = Some(value),
            "mx" => mx.push(normalize_host(value)),
            _ => {}
        }
    }
    if version != Some("STSv1") {
        bail!("policy version is not STSv1");
    }
    match mode {
        Some("enforce" | "testing") => {}
        _ => bail!("policy mode is not enforce or testing"),
    }
    let max_age = max_age.context("policy has no max_age")?;
    max_age
        .parse::<u64>()
        .context("policy max_age is not a non-negative integer")?;
    if mx.is_empty() || mx.iter().any(String::is_empty) {
        bail!("policy has no valid mx entry");
    }
    Ok(Policy { mx })
}

/// Matches `host` against the policy `mx` patterns (RFC 8461 section 4.1).
pub fn mx_matches(policy: &Policy, host: &str) -> bool {
    let host = normalize_host(host);
    policy
        .mx
        .iter()
        .any(|pattern| match pattern.strip_prefix("*.") {
            Some(suffix) => host
                .split_once('.')
                .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
            None => *pattern == host,
        })
}

/// Fetches `https://mta-sts.{domain}/.well-known/mta-sts.txt` (RFC 8461
/// section 3.3). The client must be built with
/// `redirect(reqwest::redirect::Policy::none())`; only status 200 and bodies
/// up to 64 KiB are accepted.
pub async fn fetch_policy(http: &reqwest::Client, domain: &str) -> Result<Policy> {
    let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    let mut response = http
        .get(&url)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?;
    if response.status() != reqwest::StatusCode::OK {
        bail!("{url} returned {}", response.status());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("reading policy body")? {
        if body.len() + chunk.len() > POLICY_MAX_BYTES {
            bail!("policy body exceeds {POLICY_MAX_BYTES} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    let text = String::from_utf8(body).context("policy is not UTF-8")?;
    parse_policy(&text)
}

#[derive(Deserialize)]
struct DnsResponse {
    #[serde(rename = "Answer", default)]
    answer: Vec<DnsAnswer>,
}

#[derive(Deserialize)]
struct DnsAnswer {
    #[serde(rename = "type")]
    kind: u16,
    data: String,
}

fn parse_mx_response(json: &str) -> Result<Vec<String>> {
    let response: DnsResponse = serde_json::from_str(json).context("parsing DNS JSON")?;
    let mut records = Vec::new();
    for answer in response.answer.iter().filter(|a| a.kind == MX_RECORD_TYPE) {
        let (preference, host) = answer
            .data
            .split_once(' ')
            .with_context(|| format!("malformed MX data {:?}", answer.data))?;
        let preference: u16 = preference.parse().context("malformed MX preference")?;
        records.push((preference, normalize_host(host.trim())));
    }
    if records.is_empty() {
        bail!("no MX records");
    }
    records.sort();
    Ok(records.into_iter().map(|(_, host)| host).collect())
}

/// Looks up MX hosts through the dns.google JSON API, ordered by ascending
/// preference. The answer is untrusted and is only used after filtering
/// through [`mx_matches`].
pub async fn lookup_mx(http: &reqwest::Client, domain: &str) -> Result<Vec<String>> {
    let text = http
        .get("https://dns.google/resolve")
        .query(&[("name", domain), ("type", "MX")])
        .send()
        .await
        .context("querying dns.google")?
        .error_for_status()
        .context("dns.google returned an error status")?
        .text()
        .await
        .context("reading dns.google body")?;
    parse_mx_response(&text)
}

/// Sends one message to `target` over SMTP with required STARTTLS. The
/// certificate is verified against the domain inside `tls`, not `target`.
pub async fn deliver(
    target: SocketAddr,
    tls: TlsParameters,
    helo: &str,
    message: Message,
) -> Result<()> {
    let transport =
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(target.ip().to_string())
            .port(target.port())
            .tls(Tls::Required(tls))
            .hello_name(ClientId::Domain(helo.into()))
            .timeout(Some(SMTP_TIMEOUT))
            .build();
    transport.send(message).await.context("SMTP delivery")?;
    Ok(())
}

/// TLS parameters verifying `mx_host` against the WebPKI roots only.
pub fn webpki_tls(mx_host: &str) -> Result<TlsParameters> {
    TlsParameters::builder(mx_host.to_owned())
        .certificate_store(CertificateStore::WebpkiRoots)
        .build_rustls()
        .context("building TLS parameters")
}

/// What one message says: the author's display name, the subject, and the same
/// body as plain text and as HTML.
pub struct Content {
    pub from_name: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// The sign-in code message for `app_name`, addressed to `recipient`.
pub fn code_content(app_name: &str, code: &str, recipient: &str) -> Content {
    Content {
        from_name: app_name.to_owned(),
        subject: format!("Your {app_name} sign-in code"),
        text: format!(
            "Sign in to {app_name}\n\nYour code: {code}\n\nIt expires in 5 minutes and works once.\n\nSent to {recipient} because someone asked to sign in to {app_name}. If that was not you, ignore this email and nothing happens.\n"
        ),
        html: CODE_MAIL_HTML
            .replace("{{app}}", &escape_html(app_name))
            .replace("{{code}}", &escape_html(code))
            .replace("{{email}}", &escape_html(recipient)),
    }
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn build_message(origin: &Origin, to: &Address, content: &Content) -> Result<Message> {
    let message_id = format!("<{}@{}>", uuid::Uuid::new_v4(), origin.sender.domain());
    Message::builder()
        .from(Mailbox::new(Some(content.from_name.clone()), origin.from.clone()))
        .to(Mailbox::new(None, to.clone()))
        .subject(content.subject.as_str())
        .message_id(Some(message_id))
        .envelope(Envelope::new(Some(origin.sender.clone()), vec![to.clone()])?)
        .multipart(MultiPart::alternative_plain_html(content.text.clone(), content.html.clone()))
        .context("building message")
}

/// Builds a DKIM configuration (RFC 6376) signing with `rsa-sha256` and
/// relaxed/relaxed canonicalization over From, To, Subject, Date and
/// Message-ID. `rsa_pkcs1_pem` is a PKCS#1 `BEGIN RSA PRIVATE KEY` PEM.
pub fn dkim_config(domain: &str, selector: &str, rsa_pkcs1_pem: &str) -> Result<DkimConfig> {
    let key = DkimSigningKey::new(rsa_pkcs1_pem, DkimSigningAlgorithm::Rsa)
        .context("parsing DKIM RSA private key")?;
    let headers = ["From", "To", "Subject", "Date", "Message-ID"]
        .into_iter()
        .map(HeaderName::new_from_ascii_str)
        .collect();
    Ok(DkimConfig::new(
        selector.to_owned(),
        domain.to_owned(),
        key,
        headers,
        DkimCanonicalization {
            header: DkimCanonicalizationType::Relaxed,
            body: DkimCanonicalizationType::Relaxed,
        },
    ))
}

/// Who a message comes from and how it is authenticated.
pub struct Origin {
    /// Address of the visible RFC 5322 author; each message names it.
    pub from: Address,
    /// RFC 5321 envelope sender, which SPF checks.
    pub sender: Address,
    /// Name announced in EHLO.
    pub helo: String,
    /// DKIM signer applied to every message when present.
    pub dkim: Option<DkimConfig>,
}

/// Delivers a message to the recipient's MX hosts that are allowed
/// by the domain's MTA-STS policy and returns the host that accepted it.
///
/// `dial` maps an MX hostname to the socket addresses to try, which keeps this
/// module independent of how connections leave the process. A permanent SMTP
/// error (5xx) ends the attempt immediately and is returned as is.
pub async fn send_code<D, F>(
    http: &reqwest::Client,
    origin: &Origin,
    to: &Address,
    content: &Content,
    dial: D,
) -> Result<String>
where
    D: Fn(String) -> F,
    F: Future<Output = Result<Vec<SocketAddr>>>,
{
    let domain = to.domain().to_ascii_lowercase();
    if domain.starts_with('[') || domain.parse::<IpAddr>().is_ok() {
        bail!("recipient domain is an IP literal");
    }
    let policy = fetch_policy(http, &domain).await?;
    let hosts: Vec<String> = lookup_mx(http, &domain)
        .await?
        .into_iter()
        .filter(|host| mx_matches(&policy, host))
        .collect();
    if hosts.is_empty() {
        bail!("no MX host of {domain} matches its MTA-STS policy");
    }
    let mut message = build_message(origin, to, content)?;
    if let Some(config) = &origin.dkim {
        dkim_sign(&mut message, config);
    }
    deliver_to_first(&hosts, &dial, webpki_tls, &origin.helo, &message).await
}

fn is_permanent(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<lettre::transport::smtp::Error>()
        .is_some_and(|error| error.is_permanent())
}

async fn deliver_to_first<D, F, T>(
    hosts: &[String],
    dial: &D,
    tls_for: T,
    helo: &str,
    message: &Message,
) -> Result<String>
where
    D: Fn(String) -> F,
    F: Future<Output = Result<Vec<SocketAddr>>>,
    T: Fn(&str) -> Result<TlsParameters>,
{
    let mut last_error = anyhow!("no delivery attempted");
    for host in hosts {
        let addrs = match dial(host.clone()).await {
            Ok(addrs) => addrs,
            Err(e) => {
                last_error = e.context(format!("resolving {host}"));
                continue;
            }
        };
        let tls = tls_for(host)?;
        for addr in addrs {
            match deliver(addr, tls.clone(), helo, message.clone()).await {
                Ok(()) => return Ok(host.clone()),
                Err(e) => {
                    let e = e.context(format!("delivering to {host} at {addr}"));
                    if is_permanent(&e) {
                        return Err(e);
                    }
                    last_error = e;
                }
            }
        }
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lettre::transport::smtp::client::Certificate;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{crypto::ring, ServerConfig};
    use tokio_rustls::TlsAcceptor;

    const GMAIL: &str = "version: STSv1\nmode: enforce\nmx: smtp.google.com\nmx: gmail-smtp-in.l.google.com\nmx: *.gmail-smtp-in.l.google.com\nmax_age: 86400\n";
    const OUTLOOK: &str =
        "version: STSv1\nmode: enforce\nmx: *.olc.protection.outlook.com\nmax_age: 604800\n";
    const YAHOO: &str = "version: STSv1\nmode: testing\nmx: *.am0.yahoodns.net\nmx: *.mail.gm0.yahoodns.net\nmx: *.mail.am0.yahoodns.net\nmax_age: 86400\n";

    #[test]
    fn parses_real_policies() {
        assert_eq!(parse_policy(GMAIL).unwrap().mx.len(), 3);
        assert_eq!(
            parse_policy(OUTLOOK).unwrap().mx,
            vec!["*.olc.protection.outlook.com"]
        );
        assert_eq!(parse_policy(YAHOO).unwrap().mx.len(), 3);
        let crlf = GMAIL.replace('\n', "\r\n");
        assert_eq!(parse_policy(&crlf).unwrap(), parse_policy(GMAIL).unwrap());
    }

    #[test]
    fn rejects_malformed_policies() {
        let bad = [
            "mode: enforce\nmx: a.example\nmax_age: 1\n",
            "version: STSv2\nmode: enforce\nmx: a.example\nmax_age: 1\n",
            "version: STSv1\nmode: none\nmx: a.example\nmax_age: 1\n",
            "version: STSv1\nmx: a.example\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmx: a.example\n",
            "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: soon\n",
            "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: -5\n",
        ];
        for text in bad {
            assert!(parse_policy(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn first_instance_of_a_repeated_key_wins() {
        let text = "version: STSv1\nmode: none\nmode: enforce\nmx: a.example\nmax_age: 1\n";
        assert!(parse_policy(text).is_err());
    }

    #[test]
    fn ignores_unknown_keys() {
        let text = "version: STSv1\nfuture: yes\nmode: enforce\nmx: a.example\nmax_age: 1\n";
        assert!(parse_policy(text).is_ok());
    }

    #[test]
    fn matches_mx_patterns() {
        let gmail = parse_policy(GMAIL).unwrap();
        assert!(mx_matches(&gmail, "gmail-smtp-in.l.google.com"));
        assert!(mx_matches(&gmail, "alt1.gmail-smtp-in.l.google.com."));
        assert!(mx_matches(&gmail, "SMTP.Google.COM"));
        assert!(!mx_matches(&gmail, "evil.com"));
        assert!(!mx_matches(&gmail, "l.google.com"));
        assert!(!mx_matches(&gmail, "a.b.gmail-smtp-in.l.google.com"));
        assert!(!mx_matches(&gmail, ".gmail-smtp-in.l.google.com"));
        let outlook = parse_policy(OUTLOOK).unwrap();
        assert!(mx_matches(
            &outlook,
            "outlook-com.olc.protection.outlook.com"
        ));
        assert!(!mx_matches(&outlook, "olc.protection.outlook.com"));
    }

    #[test]
    fn parses_mx_json() {
        let json = r#"{"Status":0,"Answer":[
            {"name":"x.","type":15,"TTL":1,"data":"20 Mx2.Example.COM."},
            {"name":"x.","type":16,"TTL":1,"data":"v=spf1 -all"},
            {"name":"x.","type":15,"TTL":1,"data":"5 mx1.example.com."}]}"#;
        assert_eq!(
            parse_mx_response(json).unwrap(),
            vec!["mx1.example.com", "mx2.example.com"]
        );
        assert!(parse_mx_response(r#"{"Status":3}"#).is_err());
        assert!(parse_mx_response(r#"{"Answer":[{"type":16,"data":"x"}]}"#).is_err());
    }

    struct Pki {
        ca_der: Vec<u8>,
        server: Arc<ServerConfig>,
    }

    fn pki() -> Pki {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["mx.test.example".to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &ca, &ca_key)
            .unwrap();
        let server = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        Pki {
            ca_der: ca.der().to_vec(),
            server: Arc::new(server),
        }
    }

    type Log = Arc<Mutex<Vec<String>>>;

    async fn smtp_session<S>(
        stream: S,
        offer_starttls: bool,
        reject_rcpt: bool,
        log: &Log,
    ) -> Option<S>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 mx.test.example ESMTP\r\n")
            .await
            .ok()?;
        let mut in_data = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.ok()? == 0 {
                return None;
            }
            let line = line.trim_end().to_owned();
            log.lock().unwrap().push(line.clone());
            let reply: &[u8] = if in_data {
                if line == "." {
                    in_data = false;
                    b"250 queued\r\n"
                } else {
                    continue;
                }
            } else {
                let command = line.to_ascii_uppercase();
                if command.starts_with("EHLO") {
                    if offer_starttls {
                        b"250-mx.test.example\r\n250 STARTTLS\r\n"
                    } else {
                        b"250 mx.test.example\r\n"
                    }
                } else if command == "STARTTLS" {
                    reader.get_mut().write_all(b"220 ready\r\n").await.ok()?;
                    return Some(reader.into_inner());
                } else if reject_rcpt && command.starts_with("RCPT") {
                    b"550 no such user\r\n"
                } else if command == "DATA" {
                    in_data = true;
                    b"354 go\r\n"
                } else if command == "QUIT" {
                    let _ = reader.get_mut().write_all(b"221 bye\r\n").await;
                    return None;
                } else {
                    b"250 ok\r\n"
                }
            };
            reader.get_mut().write_all(reply).await.ok()?;
        }
    }

    async fn spawn_server(
        pki: &Pki,
        offer_starttls: bool,
    ) -> (SocketAddr, Log, tokio::task::JoinHandle<()>) {
        spawn_server_with(pki, offer_starttls, false).await
    }

    async fn spawn_server_with(
        pki: &Pki,
        offer_starttls: bool,
        reject_rcpt: bool,
    ) -> (SocketAddr, Log, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log: Log = Arc::default();
        let acceptor = TlsAcceptor::from(pki.server.clone());
        let task_log = log.clone();
        let handle = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let Some(tcp) = smtp_session(tcp, offer_starttls, reject_rcpt, &task_log).await else {
                return;
            };
            let Ok(tls) = acceptor.accept(tcp).await else {
                task_log.lock().unwrap().push("TLS-HANDSHAKE-FAILED".into());
                return;
            };
            task_log.lock().unwrap().push("TLS-ESTABLISHED".into());
            smtp_session(tls, true, reject_rcpt, &task_log).await;
        });
        (addr, log, handle)
    }

    fn test_tls(pki: &Pki, name: &str, trust_ca: bool) -> TlsParameters {
        let mut builder =
            TlsParameters::builder(name.to_owned()).certificate_store(CertificateStore::None);
        if trust_ca {
            builder =
                builder.add_root_certificate(Certificate::from_der(pki.ca_der.clone()).unwrap());
        }
        builder.build_rustls().unwrap()
    }

    fn test_origin(from: &str, sender: &str) -> Origin {
        Origin {
            from: from.parse().unwrap(),
            sender: sender.parse().unwrap(),
            helo: "enclave.test".into(),
            dkim: None,
        }
    }

    fn test_message() -> Message {
        build_message(
            &test_origin("noreply@sender.example", "noreply@sender.example"),
            &"user@recipient.example".parse().unwrap(),
            &code_content("Acme", "qpzry9x8g", "user@recipient.example"),
        )
        .unwrap()
    }

    fn relaxed_header(line: &str) -> String {
        let (name, value) = line.split_once(':').unwrap();
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        format!("{}:{}\r\n", name.trim().to_ascii_lowercase(), value)
    }

    #[test]
    fn dkim_signature_verifies() {
        use base64::Engine;
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::{Pkcs1v15Sign, RsaPrivateKey};
        use sha2::{Digest, Sha256};

        let key = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let pem = key.to_pkcs1_pem(Default::default()).unwrap();
        let config = dkim_config("sender.example", "sel1", &pem).unwrap();
        let mut message = test_message();
        dkim_sign(&mut message, &config);
        let raw = String::from_utf8(message.formatted()).unwrap();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        let head = head.replace("\r\n ", " ");
        let lines: Vec<&str> = head.split("\r\n").collect();
        let signature = lines
            .iter()
            .find(|l| l.starts_with("DKIM-Signature:"))
            .unwrap();
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.starts_with("DKIM-Signature:"))
                .count(),
            1
        );
        let tags: std::collections::HashMap<&str, String> = signature
            .split_once(':')
            .unwrap()
            .1
            .split(';')
            .filter_map(|t| t.trim().split_once('='))
            .map(|(k, v)| (k, v.split_whitespace().collect()))
            .collect();
        assert_eq!(tags["a"], "rsa-sha256");
        assert_eq!(tags["d"], "sender.example");
        assert_eq!(tags["s"], "sel1");
        assert_eq!(tags["c"], "relaxed/relaxed");
        assert_eq!(tags["h"], "from:to:subject:date:message-id");

        let canonical_body = format!("{}\r\n", body.trim_end_matches("\r\n"));
        let body_hash = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(canonical_body.as_bytes()));
        assert_eq!(tags["bh"], body_hash);

        let mut signed = String::new();
        for name in tags["h"].split(':') {
            let line = lines
                .iter()
                .find(|l| l.to_ascii_lowercase().starts_with(&format!("{name}:")))
                .unwrap_or_else(|| panic!("{name} header missing at signing time"));
            signed.push_str(&relaxed_header(line));
        }
        let raw_b = signature.rsplit_once("b=").unwrap().1;
        let unsigned = signature.replace(raw_b, "");
        signed.push_str(relaxed_header(&unsigned).trim_end());
        let digest = Sha256::digest(signed.as_bytes());
        let sig = base64::engine::general_purpose::STANDARD
            .decode(&tags["b"])
            .unwrap();
        key.to_public_key()
            .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &sig)
            .unwrap();
    }

    #[test]
    fn message_declares_mime_and_uses_envelope_sender() {
        let origin = test_origin("noreply@brand.example", "bounce@mta.brand.example");
        let message = build_message(
            &origin,
            &"user@recipient.example".parse().unwrap(),
            &code_content("Acme", "qpzry9x8g", "user@recipient.example"),
        )
        .unwrap();
        let text = String::from_utf8(message.formatted()).unwrap();
        assert!(text.contains("MIME-Version: 1.0\r\n"));
        assert!(text.contains("From: Acme <noreply@brand.example>\r\n"));
        assert!(text.contains("Subject: Your Acme sign-in code\r\n"));
        assert!(text.contains("Content-Type: multipart/alternative;"));
        assert!(text.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(text.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert_eq!(message.envelope().from(), Some(&origin.sender));
    }

    #[test]
    fn code_content_fills_and_escapes_the_template() {
        let content = code_content("Acme & Co.", "qpzry9x8g", "o'neil@gmail.com");
        assert_eq!(content.from_name, "Acme & Co.");
        assert!(content.text.contains("Your code: qpzry9x8g\n"));
        assert!(content.text.contains("Sent to o'neil@gmail.com because"));
        assert!(content.html.contains("Sign in to Acme &amp; Co.<"));
        assert!(content.html.contains(">qpzry9x8g<"));
        assert!(content.html.contains("o&#39;neil@gmail.com"));
        assert!(!content.html.contains("{{"));
    }

    #[test]
    fn dkim_config_rejects_invalid_key() {
        assert!(dkim_config("sender.example", "sel1", "not a pem").is_err());
    }

    async fn run(
        pki: &Pki,
        offer_starttls: bool,
        name: &str,
        trust_ca: bool,
    ) -> (Result<()>, Vec<String>) {
        let (addr, log, handle) = spawn_server(pki, offer_starttls).await;
        let result = deliver(
            addr,
            test_tls(pki, name, trust_ca),
            "enclave.test",
            test_message(),
        )
        .await;
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .unwrap()
            .unwrap();
        let lines = log.lock().unwrap().clone();
        (result, lines)
    }

    fn saw_mail_from(lines: &[String]) -> bool {
        lines
            .iter()
            .any(|l| l.to_ascii_uppercase().starts_with("MAIL FROM"))
    }

    #[tokio::test]
    async fn delivers_when_name_and_ca_match() {
        let pki = pki();
        let (result, lines) = run(&pki, true, "mx.test.example", true).await;
        result.unwrap();
        assert!(lines.iter().any(|l| l == "TLS-ESTABLISHED"));
        assert!(lines.iter().any(|l| l.contains("Your code is qpzry9x8g")));
        assert!(lines.iter().any(|l| l.starts_with("Message-ID: <")));
        assert!(lines.iter().any(|l| l.starts_with("Date: ")));
        let first_mail = lines
            .iter()
            .position(|l| l.starts_with("MAIL FROM"))
            .unwrap();
        let tls = lines.iter().position(|l| l == "TLS-ESTABLISHED").unwrap();
        assert!(tls < first_mail);
    }

    #[tokio::test]
    async fn rejects_wrong_certificate_name() {
        let pki = pki();
        let (result, lines) = run(&pki, true, "other.test.example", true).await;
        assert!(result.is_err());
        assert!(lines.iter().any(|l| l == "TLS-HANDSHAKE-FAILED"));
        assert!(!saw_mail_from(&lines));
    }

    #[tokio::test]
    async fn rejects_untrusted_certificate() {
        let pki = pki();
        let (result, lines) = run(&pki, true, "mx.test.example", false).await;
        assert!(result.is_err());
        assert!(lines.iter().any(|l| l == "TLS-HANDSHAKE-FAILED"));
        assert!(!saw_mail_from(&lines));
    }

    #[tokio::test]
    async fn production_roots_reject_a_private_ca() {
        let pki = pki();
        let (addr, log, handle) = spawn_server(&pki, true).await;
        let tls = webpki_tls("mx.test.example").unwrap();
        let result = deliver(addr, tls, "enclave.test", test_message()).await;
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .unwrap()
            .unwrap();
        let lines = log.lock().unwrap().clone();
        assert!(result.is_err());
        assert!(lines.iter().any(|l| l == "TLS-HANDSHAKE-FAILED"));
        assert!(!saw_mail_from(&lines));
    }

    #[tokio::test]
    async fn rejects_server_without_starttls() {
        let pki = pki();
        let (result, lines) = run(&pki, false, "mx.test.example", true).await;
        assert!(result.is_err());
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("EHLO"));
    }

    #[tokio::test]
    async fn permanent_rejection_stops_further_attempts() {
        let pki = pki();
        let (addr, log, handle) = spawn_server_with(&pki, true, true).await;
        let dialed = Arc::new(Mutex::new(Vec::<String>::new()));
        let dial = {
            let dialed = dialed.clone();
            move |host: String| {
                let dialed = dialed.clone();
                async move {
                    dialed.lock().unwrap().push(host);
                    Ok(vec![addr, addr])
                }
            }
        };
        let hosts = vec!["mx1.test.example".to_owned(), "mx2.test.example".to_owned()];
        let message = test_message();
        let error = deliver_to_first(
            &hosts,
            &dial,
            |_| Ok(test_tls(&pki, "mx.test.example", true)),
            "enclave.test",
            &message,
        )
        .await
        .unwrap_err();
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(is_permanent(&error), "{error:#}");
        assert_eq!(*dialed.lock().unwrap(), vec!["mx1.test.example"]);
        let lines = log.lock().unwrap().clone();
        assert_eq!(lines.iter().filter(|l| l.starts_with("EHLO")).count(), 2);
    }

    #[tokio::test]
    async fn transient_failures_fall_through_to_the_next_host() {
        let pki = pki();
        let (addr, _log, handle) = spawn_server(&pki, true).await;
        let dial = move |host: String| async move {
            if host == "mx1.test.example" {
                Err(anyhow!("no such host"))
            } else {
                Ok(vec![addr])
            }
        };
        let hosts = vec!["mx1.test.example".to_owned(), "mx2.test.example".to_owned()];
        let message = test_message();
        let accepted = deliver_to_first(
            &hosts,
            &dial,
            |_| Ok(test_tls(&pki, "mx.test.example", true)),
            "enclave.test",
            &message,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted, "mx2.test.example");
    }

    /// Reaches the real policy and DNS hosts; run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_policies_admit_a_published_mx() {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for domain in [
            "gmail.com",
            "outlook.com",
            "hotmail.com",
            "yahoo.com",
            "proton.me",
        ] {
            let policy = fetch_policy(&http, domain).await.unwrap();
            let hosts = lookup_mx(&http, domain).await.unwrap();
            assert!(
                hosts.iter().any(|host| mx_matches(&policy, host)),
                "{domain}: {hosts:?} not admitted by {policy:?}"
            );
        }
    }
}

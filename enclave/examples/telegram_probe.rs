//! Local probe for Telegram sign-in against a real bot:
//! `TELEGRAM_CLIENT_SECRET=… telegram_probe <bot-id> <public-base-url> [port]`.
//!
//! Serves a page that starts logins and receives the callback, behind an HTTPS
//! tunnel such as `cloudflared tunnel --url http://localhost:8787`. The bot's
//! Allowed URLs must list `<public-base-url>/callback`.
//!
//! `/start` runs the enclave's own `telegram::user_for_code` on the callback,
//! exactly as a `verify_telegram` job does, and shows the token the enclave
//! would sign. `/raw?variant=…` redeems the code by hand and shows what
//! Telegram answered, for the measurements the enclave code does not expose:
//! `normal`, `no_verifier`, `bad_verifier`, `no_secret`, `reuse` and
//! `other_redirect`.

#![allow(dead_code)]

#[path = "../src/failure.rs"]
mod failure;
#[path = "../src/github.rs"]
mod github;
#[path = "../src/login.rs"]
mod login;
#[path = "../src/oidc.rs"]
mod oidc;
#[path = "../src/protocol.rs"]
mod protocol;
#[path = "../src/telegram.rs"]
mod telegram;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const APP_ID: &str = "0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f";

struct Pending {
    login_secret: String,
    verifier: String,
    variant: Option<String>,
    started: Instant,
}

struct Probe {
    bot_id: String,
    client_secret: String,
    callback: String,
    http: reqwest::Client,
    pending: Mutex<HashMap<String, Pending>>,
}

fn random_b64(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buffer);
    URL_SAFE_NO_PAD.encode(buffer)
}

fn s256(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn claims_of(token: &str) -> Result<serde_json::Value> {
    let payload = token.split('.').nth(1).context("token has no payload")?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?)
}

impl Probe {
    async fn start(&self, variant: Option<String>) -> String {
        let login_secret = random_b64(32);
        let verifier = random_b64(32);
        let state = random_b64(16);
        let nonce = format!("{APP_ID}.{}", s256(&login_secret));
        let url = url::Url::parse_with_params(
            "https://oauth.telegram.org/auth",
            &[
                ("client_id", self.bot_id.as_str()),
                ("response_type", "code"),
                ("scope", "openid profile"),
                ("redirect_uri", self.callback.as_str()),
                ("code_challenge", s256(&verifier).as_str()),
                ("code_challenge_method", "S256"),
                ("nonce", nonce.as_str()),
                ("state", state.as_str()),
            ],
        )
        .expect("static URL");
        self.pending.lock().await.insert(
            state,
            Pending { login_secret, verifier, variant, started: Instant::now() },
        );
        url.to_string()
    }

    async fn callback(&self, query: &HashMap<String, String>) -> Result<String> {
        if let Some(error) = query.get("error") {
            bail!("Telegram answered error={error}");
        }
        let state = query.get("state").context("callback has no state")?;
        let code = query.get("code").context("callback has no code")?;
        let pending = self.pending.lock().await.remove(state).context("unknown or spent state")?;
        let elapsed = pending.started.elapsed();
        let report = match pending.variant.as_deref() {
            None => self.enclave_path(code, &pending).await,
            Some(variant) => self.raw_path(code, &pending, variant).await,
        }?;
        Ok(format!("<p>From /start to callback: {elapsed:.1?}</p>{report}"))
    }

    async fn enclave_path(&self, code: &str, pending: &Pending) -> Result<String> {
        let grant = protocol::TelegramGrant {
            code: code.into(),
            app_id: APP_ID.into(),
            bot_id: self.bot_id.clone(),
            client_secret: self.client_secret.clone(),
            redirect_uri: self.callback.clone(),
        };
        let nonce = format!("{APP_ID}.{}", s256(&pending.login_secret));
        let redeem_started = Instant::now();
        let user = telegram::user_for_code(&self.http, &grant, &pending.verifier, &nonce)
            .await
            .map_err(|error| anyhow::anyhow!("{} ({error:#})", failure::classify(&error)))?;
        let redeemed_in = redeem_started.elapsed();
        let key = login::LoginKey::new(p256::SecretKey::random(&mut OsRng))?;
        let token = key.issue_telegram(&user, &self.bot_id, &nonce, oidc::unix_time()?)?;
        Ok(format!(
            "<h2>Enclave path accepted the sign-in</h2><p>Redeem and verify: {redeemed_in:.1?}</p>\
             <pre>{}</pre><h3>Token the enclave would sign</h3><pre>{}</pre>",
            escape(&format!("{user:#?}")),
            escape(&serde_json::to_string_pretty(&claims_of(&token)?)?),
        ))
    }

    async fn redeem(
        &self,
        code: &str,
        verifier: Option<&str>,
        secret: bool,
        redirect_uri: &str,
    ) -> Result<(u16, String)> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", self.bot_id.as_str()),
        ];
        if let Some(verifier) = verifier {
            form.push(("code_verifier", verifier));
        }
        let mut request = self.http.post("https://oauth.telegram.org/token").form(&form);
        if secret {
            request = request.basic_auth(&self.bot_id, Some(&self.client_secret));
        }
        let response = request.send().await?;
        let status = response.status().as_u16();
        Ok((status, response.text().await?))
    }

    async fn raw_path(&self, code: &str, pending: &Pending, variant: &str) -> Result<String> {
        let other_redirect = format!("{}-other", self.callback);
        let wrong_verifier = random_b64(32);
        let attempts: Vec<(&str, Option<&str>, bool, &str)> = match variant {
            "normal" => vec![("normal", Some(&pending.verifier), true, &self.callback)],
            "no_verifier" => vec![("no code_verifier", None, true, &self.callback)],
            "bad_verifier" => vec![("wrong code_verifier", Some(&wrong_verifier), true, &self.callback)],
            "no_secret" => vec![("no client_secret", Some(&pending.verifier), false, &self.callback)],
            "reuse" => vec![
                ("first redemption", Some(&pending.verifier), true, &self.callback),
                ("same code again", Some(&pending.verifier), true, &self.callback),
            ],
            "other_redirect" => vec![("redirect_uri with another path", Some(&pending.verifier), true, &other_redirect)],
            other => bail!("unknown variant {other}"),
        };
        let expected_nonce = format!("{APP_ID}.{}", s256(&pending.login_secret));
        let mut report = String::new();
        for (label, verifier, secret, redirect_uri) in attempts {
            let (status, body) = self.redeem(code, verifier, secret, redirect_uri).await?;
            let now = oidc::unix_time()?;
            report.push_str(&format!("<h2>{label}: HTTP {status}</h2>"));
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
            match parsed.get("id_token").and_then(serde_json::Value::as_str) {
                Some(token) => {
                    let claims = claims_of(token)?;
                    let iat = claims["iat"].as_u64().unwrap_or(0);
                    let exp = claims["exp"].as_u64().unwrap_or(0);
                    let header: serde_json::Value = serde_json::from_slice(
                        &URL_SAFE_NO_PAD.decode(token.split('.').next().unwrap_or_default())?,
                    )?;
                    report.push_str(&format!(
                        "<p>exp − iat = {}s · now − iat = {}s · nonce matches: {} · id type: {}</p>\
                         <pre>header {}</pre><pre>{}</pre><p>other response keys: {:?}</p>",
                        exp.saturating_sub(iat),
                        now as i64 - iat as i64,
                        claims["nonce"].as_str() == Some(expected_nonce.as_str()),
                        match &claims["id"] {
                            serde_json::Value::String(_) => "string",
                            serde_json::Value::Number(_) => "number",
                            serde_json::Value::Null => "absent",
                            _ => "other",
                        },
                        escape(&header.to_string()),
                        escape(&serde_json::to_string_pretty(&claims)?),
                        parsed.as_object().map(|o| o.keys().filter(|k| *k != "id_token").cloned().collect::<Vec<_>>()),
                    ));
                }
                None => report.push_str(&format!("<pre>{}</pre>", escape(&body))),
            }
        }
        Ok(report)
    }
}

fn index() -> String {
    let variants = ["normal", "no_verifier", "bad_verifier", "no_secret", "reuse", "other_redirect"];
    let raw: String = variants
        .iter()
        .map(|variant| format!("<li><a href=\"/raw?variant={variant}\">raw: {variant}</a></li>"))
        .collect();
    format!(
        "<h1>Telegram probe</h1><ul><li><a href=\"/start\">enclave path (telegram::user_for_code)</a></li>{raw}</ul>"
    )
}

async fn respond(mut stream: TcpStream, status: &str, extra: &str, body: &str) {
    let page = format!("<!doctype html><meta charset=utf-8><body style=\"font-family:system-ui;max-width:900px;margin:40px auto\">{body}<p><a href=\"/\">back</a></p>");
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/html; charset=utf-8\r\ncache-control: no-store\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn serve(probe: Arc<Probe>, mut stream: TcpStream) {
    let mut buffer = vec![0u8; 16 * 1024];
    let read = match stream.read(&mut buffer).await {
        Ok(read) => read,
        Err(_) => return,
    };
    let request = String::from_utf8_lossy(&buffer[..read]);
    let target = request.split_whitespace().nth(1).unwrap_or("/").to_string();
    let url = match url::Url::parse(&format!("http://probe{target}")) {
        Ok(url) => url,
        Err(_) => return respond(stream, "400 Bad Request", "", "bad request").await,
    };
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    match url.path() {
        "/" => respond(stream, "200 OK", "", &index()).await,
        "/start" | "/raw" => {
            let variant = (url.path() == "/raw")
                .then(|| query.get("variant").cloned().unwrap_or_else(|| "normal".into()));
            let location = probe.start(variant).await;
            respond(stream, "302 Found", &format!("location: {location}\r\n"), "redirecting").await
        }
        "/callback" => match probe.callback(&query).await {
            Ok(report) => respond(stream, "200 OK", "", &report).await,
            Err(error) => {
                respond(stream, "200 OK", "", &format!("<h2>Refused</h2><pre>{}</pre>", escape(&format!("{error:#}")))).await
            }
        },
        _ => respond(stream, "404 Not Found", "", "not found").await,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let bot_id = args.next().context("usage: telegram_probe <bot-id> <public-base-url> [port]")?;
    let base = args.next().context("usage: telegram_probe <bot-id> <public-base-url> [port]")?;
    let port: u16 = args.next().map(|port| port.parse()).transpose()?.unwrap_or(8787);
    let client_secret = std::env::var("TELEGRAM_CLIENT_SECRET").context("set TELEGRAM_CLIENT_SECRET")?;
    let probe = Arc::new(Probe {
        bot_id,
        client_secret,
        callback: format!("{}/callback", base.trim_end_matches('/')),
        http: reqwest::Client::builder().build()?,
        pending: Mutex::new(HashMap::new()),
    });
    eprintln!("Allowed URL for the bot: {}", probe.callback);
    eprintln!("Open {}/ in a browser", base.trim_end_matches('/'));
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(serve(probe.clone(), stream));
    }
}

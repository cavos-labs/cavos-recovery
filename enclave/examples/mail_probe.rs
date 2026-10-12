//! One-off deliverability probe:
//! `mail_probe <app-name> <from-address> <envelope-sender> <helo-hostname> <recipient>...`.
//! Set `DKIM_KEY_FILE` (PKCS#1 RSA PEM) and `DKIM_SELECTOR` to sign with the
//! envelope-sender domain; an unreadable or invalid key aborts the run.

#[path = "../src/mail.rs"]
mod mail;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use lettre::Address;
use rand_core::{OsRng, RngCore};

const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn random_code() -> String {
    let mut bytes = [0u8; 9];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| BECH32[(b & 31) as usize] as char)
        .collect()
}

const SMTP_PORT: u16 = 25;

async fn dial(host: String) -> Result<Vec<SocketAddr>> {
    let addrs = tokio::net::lookup_host((host.as_str(), SMTP_PORT))
        .await
        .with_context(|| format!("resolving {host}"))?
        .filter(SocketAddr::is_ipv4)
        .collect();
    Ok(addrs)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 5 {
        eprintln!(
            "usage: mail_probe <app-name> <from-address> <envelope-sender> <helo-hostname> <recipient>..."
        );
        std::process::exit(2);
    }
    let sender: Address = args[2].parse().context("envelope sender")?;
    let dkim = match std::env::var_os("DKIM_KEY_FILE") {
        Some(path) => {
            let pem = std::fs::read_to_string(&path).context("reading DKIM_KEY_FILE")?;
            let selector = std::env::var("DKIM_SELECTOR").context("DKIM_SELECTOR")?;
            Some(mail::dkim_config(sender.domain(), &selector, &pem)?)
        }
        None => None,
    };
    let origin = mail::Origin {
        from: args[1].parse().context("from address")?,
        sender,
        helo: args[3].clone(),
        dkim,
    };
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .context("building HTTP client")?;

    let mut failed = false;
    for recipient in &args[4..] {
        let started = Instant::now();
        let outcome = match recipient.parse::<Address>() {
            Ok(to) => {
                let content = mail::code_content(&args[0], &random_code(), recipient);
                mail::send_code(&http, &origin, &to, &content, dial).await
            }
            Err(e) => Err(anyhow::Error::new(e).context("recipient address")),
        };
        let elapsed = started.elapsed().as_millis();
        match outcome {
            Ok(host) => println!("{recipient} ok via {host} {elapsed}ms"),
            Err(e) => {
                failed = true;
                println!("{recipient} failed: {e:#} {elapsed}ms");
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
    Ok(())
}

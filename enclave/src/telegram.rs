//! Telegram sign-in: trade an authorization code for the account it belongs to.
//!
//! Telegram is an OpenID Connect provider (`https://oauth.telegram.org`), but
//! its id_token cannot stand in for a Google one: it lives about thirty
//! seconds, and its `sub` differs for every bot. So the enclave redeems the
//! code itself, verifies the id_token on the spot, and signs a token of its
//! own, exactly as it does for GitHub. The identity is the `id` claim, the
//! numeric Telegram user id, which Telegram sends only with the `profile`
//! scope and which is the same for every bot.

use anyhow::{anyhow, bail, Context, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::failure::Failure;
use crate::oidc::{self, MAX_PROVIDER_RESPONSE_BYTES};
use crate::protocol::TelegramGrant;

const ISSUER: &str = "https://oauth.telegram.org";
const TOKEN_URL: &str = "https://oauth.telegram.org/token";
const JWKS_URL: &str = "https://oauth.telegram.org/.well-known/jwks.json";
const CLOCK_SKEW_SECONDS: u64 = 30;
const MAX_AUTH_AGE_SECONDS: u64 = 5 * 60;
const MAX_NAME_CHARS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramUser {
    /// The Telegram user id, in canonical decimal form.
    pub id: String,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct Claims {
    iat: u64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
}

/// Redeem `grant.code` with the client's PKCE `code_verifier` and return the
/// account Telegram's id_token names, once that token is proven to be
/// Telegram's, for this bot, current, and bound to `expected_nonce`.
///
/// Telegram answers a refused code with HTTP 200 and `{"error": …}`, so the
/// status is not read: only a body carrying an id_token is a success. The code,
/// secret, verifier and token are never logged.
pub async fn user_for_code(
    http: &reqwest::Client,
    grant: &TelegramGrant,
    code_verifier: &str,
    expected_nonce: &str,
) -> Result<TelegramUser> {
    let response = http
        .post(TOKEN_URL)
        .basic_auth(&grant.bot_id, Some(&grant.client_secret))
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", grant.code.as_str()),
            ("redirect_uri", grant.redirect_uri.as_str()),
            ("client_id", grant.bot_id.as_str()),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|_| anyhow!("oauth.telegram.org request failed"))
        .context(Failure::TelegramUnreachable)?;
    let body = oidc::read_limited(response, MAX_PROVIDER_RESPONSE_BYTES)
        .await
        .map_err(|_| anyhow!("oauth.telegram.org answered unreadably"))
        .context(Failure::TelegramUnreachable)?;
    let id_token = serde_json::from_slice::<TokenResponse>(&body)
        .ok()
        .and_then(|response| response.id_token)
        .ok_or_else(|| anyhow!("oauth.telegram.org returned no id_token"))
        .context(Failure::TelegramRejected)?;

    let header = decode_header(&id_token)
        .map_err(|_| anyhow!("Telegram id_token header is invalid"))
        .context(Failure::TelegramRejected)?;
    let kid = header
        .kid
        .ok_or_else(|| anyhow!("Telegram id_token names no key"))
        .context(Failure::TelegramRejected)?;
    let (algorithm, key) = oidc::jwks_key(http, JWKS_URL, &kid).await?;
    verify_id_token(
        &id_token,
        algorithm,
        &key,
        &grant.bot_id,
        expected_nonce,
        oidc::unix_time()?,
    )
    .context(Failure::TelegramRejected)
}

/// Check a Telegram id_token against the key that `kid` named and return the
/// user it carries.
fn verify_id_token(
    token: &str,
    algorithm: Algorithm,
    key: &DecodingKey,
    bot_id: &str,
    expected_nonce: &str,
    now: u64,
) -> Result<TelegramUser> {
    let header = decode_header(token).context("invalid id_token header")?;
    if header.alg != algorithm {
        bail!("id_token alg does not match its key");
    }
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[bot_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.validate_exp = true;
    validation.leeway = CLOCK_SKEW_SECONDS;
    let claims = decode::<Claims>(token, key, &validation)
        .context("id_token signature or claims rejected")?
        .claims;

    if claims.iat > now.saturating_add(CLOCK_SKEW_SECONDS) {
        bail!("id_token is dated in the future");
    }
    if now.saturating_sub(claims.iat) > MAX_AUTH_AGE_SECONDS {
        bail!("id_token is too old");
    }
    let nonce = claims
        .nonce
        .as_deref()
        .context("id_token carries no nonce")?;
    if nonce
        .as_bytes()
        .ct_eq(expected_nonce.as_bytes())
        .unwrap_u8()
        != 1
    {
        bail!("id_token is not bound to this login");
    }
    let id = canonical_user_id(claims.id.as_ref()).context("id_token carries no usable user id")?;
    Ok(TelegramUser {
        id,
        name: bounded(claims.name),
        preferred_username: bounded(claims.preferred_username),
    })
}

/// The `id` claim as canonical decimal: a positive integer with no leading
/// zero and at most twenty digits. Telegram sends it as a string; a JSON number
/// is accepted only if it is an exact unsigned integer.
fn canonical_user_id(value: Option<&serde_json::Value>) -> Option<String> {
    let id = match value? {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Number(number) => number.as_u64()?.to_string(),
        _ => return None,
    };
    let canonical = (1..=20).contains(&id.len())
        && !id.starts_with('0')
        && id.bytes().all(|byte| byte.is_ascii_digit());
    canonical.then_some(id)
}

fn bounded(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.is_empty() && text.chars().count() <= MAX_NAME_CHARS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use p256::{ecdsa::SigningKey, pkcs8::EncodePrivateKey, SecretKey};
    use serde_json::json;

    const BOT: &str = "8521897198";
    const NONCE: &str =
        "0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f.E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    struct Keys {
        encoding: EncodingKey,
        decoding: DecodingKey,
    }

    fn keys(seed: u8) -> Keys {
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
        let point = SigningKey::from(secret.clone())
            .verifying_key()
            .to_encoded_point(false);
        let pem = secret.to_pkcs8_pem(Default::default()).unwrap();
        Keys {
            encoding: EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
            decoding: DecodingKey::from_ec_components(
                &URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                &URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            )
            .unwrap(),
        }
    }

    fn now() -> u64 {
        oidc::unix_time().unwrap()
    }

    fn claims() -> serde_json::Value {
        let now = now();
        json!({
            "iss": ISSUER,
            "aud": BOT,
            "sub": "1234567890123456789",
            "id": "123456789",
            "iat": now,
            "exp": now + 30,
            "nonce": NONCE,
            "name": "Ada Lovelace",
            "preferred_username": "ada",
        })
    }

    fn sign(keys: &Keys, claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("oidc-es256-1".into());
        encode(&header, claims, &keys.encoding).unwrap()
    }

    fn check(token: &str, keys: &Keys) -> Result<TelegramUser> {
        verify_id_token(token, Algorithm::ES256, &keys.decoding, BOT, NONCE, now())
    }

    fn with(field: &str, value: serde_json::Value) -> serde_json::Value {
        let mut claims = claims();
        claims[field] = value;
        claims
    }

    fn without(field: &str) -> serde_json::Value {
        let mut claims = claims();
        claims.as_object_mut().unwrap().remove(field);
        claims
    }

    #[test]
    fn accepts_a_current_bound_token_and_reads_the_user_id() {
        let keys = keys(3);
        let user = check(&sign(&keys, &claims()), &keys).unwrap();
        assert_eq!(
            user,
            TelegramUser {
                id: "123456789".into(),
                name: Some("Ada Lovelace".into()),
                preferred_username: Some("ada".into()),
            }
        );
    }

    #[test]
    fn accepts_a_numeric_user_id() {
        let keys = keys(3);
        let user = check(&sign(&keys, &with("id", json!(123456789u64))), &keys).unwrap();
        assert_eq!(user.id, "123456789");
    }

    #[test]
    fn refuses_a_token_signed_by_another_key() {
        let token = sign(&keys(4), &claims());
        assert!(check(&token, &keys(3)).is_err());
    }

    #[test]
    fn refuses_an_algorithm_other_than_the_keys() {
        let keys = keys(3);
        let token = sign(&keys, &claims());
        assert!(
            verify_id_token(&token, Algorithm::RS256, &keys.decoding, BOT, NONCE, now()).is_err()
        );
    }

    #[test]
    fn refuses_another_issuer_or_bot() {
        let keys = keys(3);
        for claims in [
            with("iss", json!("https://accounts.google.com")),
            with("iss", json!("https://oauth.telegram.org/")),
            with("aud", json!("8521897199")),
            with("aud", json!(["8521897199"])),
            without("iss"),
            without("aud"),
        ] {
            assert!(check(&sign(&keys, &claims), &keys).is_err(), "{claims}");
        }
    }

    #[test]
    fn refuses_expired_stale_or_future_tokens() {
        let keys = keys(3);
        let now = now();
        for claims in [
            with("exp", json!(now - 120)),
            without("exp"),
            with("iat", json!(now - MAX_AUTH_AGE_SECONDS - 60)),
            with("iat", json!(now + 120)),
        ] {
            assert!(check(&sign(&keys, &claims), &keys).is_err(), "{claims}");
        }
    }

    #[test]
    fn refuses_a_token_bound_to_another_login_or_app() {
        let keys = keys(3);
        for claims in [
            without("nonce"),
            with("nonce", json!("")),
            with("nonce", json!("0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f.other")),
            with("nonce", json!("aaaaaaaa-3b2e-4c5a-8d7f-1a2b3c4d5e6f.E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")),
            with("nonce", json!(format!("{NONCE}x"))),
        ] {
            assert!(check(&sign(&keys, &claims), &keys).is_err(), "{claims}");
        }
    }

    #[test]
    fn refuses_a_token_without_a_canonical_user_id() {
        let keys = keys(3);
        for claims in [
            without("id"),
            with("id", json!("")),
            with("id", json!("0")),
            with("id", json!("0123")),
            with("id", json!("12a")),
            with("id", json!("-5")),
            with("id", json!(" 123")),
            with("id", json!("123456789012345678901")),
            with("id", json!(-5)),
            with("id", json!(1.5)),
            with("id", json!(null)),
            with("id", json!(["123"])),
        ] {
            assert!(check(&sign(&keys, &claims), &keys).is_err(), "{claims}");
        }
    }

    #[test]
    fn drops_names_that_are_empty_or_oversized() {
        let keys = keys(3);
        let mut claims = with("name", json!("x".repeat(MAX_NAME_CHARS + 1)));
        claims["preferred_username"] = json!("");
        let user = check(&sign(&keys, &claims), &keys).unwrap();
        assert_eq!(user.name, None);
        assert_eq!(user.preferred_username, None);
    }

    #[tokio::test]
    #[ignore = "reaches oauth.telegram.org"]
    async fn reads_telegram_keys_live_over_fresh_connections() {
        for _ in 0..20 {
            let http = reqwest::Client::builder()
                .no_proxy()
                .pool_max_idle_per_host(0)
                .build()
                .unwrap();
            let (algorithm, _) = oidc::jwks_key(&http, JWKS_URL, "oidc-1").await.unwrap();
            assert_eq!(algorithm, Algorithm::RS256);
        }
    }

    #[test]
    fn the_token_response_needs_an_id_token_whatever_its_status() {
        let parsed = |body: &str| {
            serde_json::from_slice::<TokenResponse>(body.as_bytes())
                .ok()
                .and_then(|response| response.id_token)
        };
        assert_eq!(parsed(r#"{"error":"invalid_grant"}"#), None);
        assert_eq!(parsed(r#"{"access_token":"x"}"#), None);
        assert_eq!(parsed("not json"), None);
        assert_eq!(parsed(r#"{"id_token":"a.b.c"}"#).as_deref(), Some("a.b.c"));
    }
}

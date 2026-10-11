use anyhow::{anyhow, bail, Context, Result};

use crate::failure::Failure;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

use crate::protocol::{ProviderCredential, RecoveryPolicy, SocialProvider};

const MAX_AUTH_AGE_SECONDS: u64 = 5 * 60;
const CLOCK_SKEW_SECONDS: u64 = 30;

#[derive(Debug, Deserialize)]
pub struct IdentityClaims {
    pub sub: String,
    pub iss: String,
    #[serde(default)]
    pub aud: Audience,
    #[serde(rename = "exp")]
    pub _exp: u64,
    pub iat: u64,
    #[serde(default)]
    pub auth_time: Option<u64>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub email_verified: Option<serde_json::Value>,
    #[serde(default)]
    pub firebase: Option<FirebaseClaims>,
}

#[derive(Debug, Deserialize)]
pub struct FirebaseClaims {
    #[serde(default)]
    pub sign_in_provider: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
    #[default]
    Missing,
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
            Self::Missing => false,
        }
    }
}

pub async fn verify_id_token(
    http: &reqwest::Client,
    credential: &ProviderCredential,
    policy: &RecoveryPolicy,
    expected_auth_challenge_hash: &str,
) -> Result<IdentityClaims> {
    validate_provider_policy(policy).context(Failure::PolicyRejected)?;
    verify_credential_binding(credential, expected_auth_challenge_hash)
        .context(Failure::CredentialBinding)?;
    let token = &credential.id_token;
    let header = decode_header(token)
        .context("invalid OIDC token header")
        .context(Failure::SignatureRejected)?;
    let kid = header
        .kid
        .context("OIDC token omitted kid")
        .context(Failure::SignatureRejected)?;
    let jwks: JwkSet = http
        .get(&policy.jwks_uri)
        .send()
        .await
        .context("JWKS request failed")
        .context(Failure::JwksUnreachable)?
        .error_for_status()
        .context("JWKS endpoint rejected request")
        .context(Failure::JwksUnreachable)?
        .json()
        .await
        .context("invalid JWKS")
        .context(Failure::JwksUnreachable)?;
    let jwk = jwks
        .keys
        .iter()
        .find(|key| key.common.key_id.as_deref() == Some(kid.as_str()))
        .context("OIDC signing key not found")
        .context(Failure::SignatureRejected)?;

    let (algorithm, decoding_key) = match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa) => (
            Algorithm::RS256,
            DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
                .context("invalid RSA JWK")?,
        ),
        AlgorithmParameters::EllipticCurve(ec) => {
            let x = URL_SAFE_NO_PAD.decode(&ec.x)?;
            let y = URL_SAFE_NO_PAD.decode(&ec.y)?;
            (
                Algorithm::ES256,
                DecodingKey::from_ec_components(&URL_SAFE_NO_PAD.encode(x), &URL_SAFE_NO_PAD.encode(y))
                    .context("invalid EC JWK")?,
            )
        }
        _ => bail!("unsupported OIDC signing key type"),
    };
    if header.alg != algorithm {
        return Err(anyhow!("OIDC alg/key mismatch").context(Failure::SignatureRejected));
    }

    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[policy.issuer.as_str()]);
    validation.set_audience(&[policy.audience.as_str()]);
    validation.validate_exp = true;
    validation.leeway = 30;
    let claims = decode::<IdentityClaims>(token, &decoding_key, &validation)
        .context("OIDC signature/claims verification failed")
        .context(Failure::ClaimsRejected)?
        .claims;
    if claims.iss != policy.issuer || !claims.aud.contains(&policy.audience) {
        return Err(anyhow!("OIDC issuer or audience mismatch").context(Failure::ClaimsRejected));
    }
    let email_verified = match claims.email_verified.as_ref() {
        Some(serde_json::Value::Bool(true)) => true,
        Some(serde_json::Value::String(value)) => value == "true",
        _ => false,
    };
    if matches!(policy.provider, SocialProvider::Email) && !email_verified {
        return Err(anyhow!("email identity is not verified").context(Failure::ClaimsRejected));
    }
    enforce_recent_auth(&claims, &policy.provider, unix_time()?).context(Failure::AuthStale)?;
    verify_login_binding(&claims, credential, policy).context(Failure::CredentialBinding)?;
    Ok(claims)
}

/// Length of a base64url-encoded SHA-256, and the least a login secret may be.
const HASH_B64_LEN: usize = 43;

/// Check that this token was minted for this app, at the request of whoever
/// holds the login secret.
///
/// The provider signs one value the client chooses: the `nonce`. The login
/// sends `<app_id>.<base64url(SHA-256(secret))>`, where the control plane
/// supplies the app after validating it and the client supplies the hash
/// (OpenID Connect Core §15.5.2; the hash is PKCE's S256, RFC 7636 §4.2).
///
/// Both halves matter. Without the app, a token one app obtains for a user is
/// good against that user's wallet in every other app, since they share an
/// audience. Without the secret, anyone who sees the token in transit can
/// spend it.
///
/// Apple is also accepted with the nonce hashed once more, hex-encoded, which
/// is the second form the control plane's callback already tolerates. Either
/// form is a function of the same two inputs, so accepting both weakens
/// nothing.
fn verify_login_binding(
    claims: &IdentityClaims,
    credential: &ProviderCredential,
    policy: &RecoveryPolicy,
) -> Result<()> {
    if matches!(policy.provider, SocialProvider::Email) {
        // A Firebase email token has no nonce the login could have set.
        return Ok(());
    }
    let secret = credential
        .nonce_preimage
        .as_deref()
        .filter(|secret| secret.len() >= HASH_B64_LEN)
        .context("credential carries no login secret")?;
    let nonce = claims.nonce.as_deref().context("OIDC token carries no nonce")?;
    let expected = format!(
        "{}.{}",
        policy.app_id,
        URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
    );

    let matches = |candidate: &str| bool::from(nonce.as_bytes().ct_eq(candidate.as_bytes()));
    if matches(&expected)
        || (matches!(policy.provider, SocialProvider::Apple)
            && matches(&hex_sha256(expected.as_bytes())))
    {
        return Ok(());
    }
    bail!("OIDC token is not bound to this app and login")
}

fn verify_credential_binding(
    credential: &ProviderCredential,
    expected_auth_challenge_hash: &str,
) -> Result<()> {
    let fingerprint = URL_SAFE_NO_PAD.encode(Sha256::digest(credential.id_token.as_bytes()));
    if fingerprint.len() != 43
        || credential.token_fingerprint.len() != 43
        || fingerprint
            .as_bytes()
            .ct_eq(credential.token_fingerprint.as_bytes())
            .unwrap_u8()
            != 1
    {
        bail!("social credential fingerprint mismatch");
    }
    let stored_hash = hex_sha256(credential.token_fingerprint.as_bytes());
    if expected_auth_challenge_hash.len() != 64
        || stored_hash
            .as_bytes()
            .ct_eq(expected_auth_challenge_hash.as_bytes())
            .unwrap_u8()
            != 1
    {
        bail!("social credential is not bound to this recovery session");
    }
    Ok(())
}

fn enforce_recent_auth(
    claims: &IdentityClaims,
    provider: &SocialProvider,
    now: u64,
) -> Result<()> {
    let authenticated_at = claims.auth_time.unwrap_or(claims.iat);
    if authenticated_at > now.saturating_add(CLOCK_SKEW_SECONDS) {
        bail!("social authentication time is in the future");
    }
    if now.saturating_sub(authenticated_at) > MAX_AUTH_AGE_SECONDS {
        bail!("social authentication is too old; sign in again");
    }

    if matches!(provider, SocialProvider::Email) {
        let sign_in_provider = claims
            .firebase
            .as_ref()
            .and_then(|firebase| firebase.sign_in_provider.as_deref());
        if !matches!(sign_in_provider, Some("password") | Some("emailLink")) {
            bail!("Firebase token was not issued by the email provider");
        }
    }
    Ok(())
}

fn unix_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

fn hex_sha256(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_provider_policy(policy: &RecoveryPolicy) -> Result<()> {
    let allowed = match policy.provider {
        SocialProvider::Google => {
            (policy.issuer == "https://accounts.google.com"
                || policy.issuer == "accounts.google.com")
                && policy.jwks_uri == "https://www.googleapis.com/oauth2/v3/certs"
        }
        SocialProvider::Apple => {
            policy.issuer == "https://appleid.apple.com"
                && policy.jwks_uri == "https://appleid.apple.com/auth/keys"
        }
        SocialProvider::Email => {
            policy.issuer.starts_with("https://securetoken.google.com/")
                && policy.jwks_uri
                    == "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
        }
    };
    if !allowed {
        bail!("provider issuer/JWKS combination is not allowlisted");
    }
    if policy.app_id.is_empty()
        || policy.environment_id.is_empty()
        || policy.audience.is_empty()
    {
        bail!("recovery policy is incomplete");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(
        issued_at: u64,
        nonce: Option<&str>,
        firebase_provider: Option<&str>,
    ) -> IdentityClaims {
        IdentityClaims {
            sub: "user-1".into(),
            iss: "issuer".into(),
            aud: Audience::One("audience".into()),
            _exp: issued_at + 3_600,
            iat: issued_at,
            auth_time: None,
            nonce: nonce.map(str::to_owned),
            email_verified: Some(serde_json::Value::Bool(true)),
            firebase: firebase_provider.map(|provider| FirebaseClaims {
                sign_in_provider: Some(provider.into()),
            }),
        }
    }

    #[test]
    fn credential_fingerprint_is_bound_to_the_stored_session_hash() {
        let token = "header.payload.signature";
        let fingerprint = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
        let credential = ProviderCredential {
            provider: SocialProvider::Google,
            id_token: token.into(),
            token_fingerprint: fingerprint.clone(),
            nonce_preimage: None,
        };
        let expected = hex_sha256(fingerprint.as_bytes());
        assert!(verify_credential_binding(&credential, &expected).is_ok());
        assert!(verify_credential_binding(&credential, &"0".repeat(64)).is_err());
    }

    #[test]
    fn provider_login_must_be_recent() {
        let now = 2_000_000_000;
        let recent = claims(now - 60, None, None);
        assert!(enforce_recent_auth(&recent, &SocialProvider::Google, now).is_ok());

        let stale = claims(now - MAX_AUTH_AGE_SECONDS - 1, None, None);
        assert!(enforce_recent_auth(&stale, &SocialProvider::Google, now).is_err());
    }

    const APP: &str = "0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f";
    const SECRET: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn policy(provider: SocialProvider) -> RecoveryPolicy {
        RecoveryPolicy {
            app_id: APP.into(),
            environment_id: "env".into(),
            provider,
            issuer: "issuer".into(),
            audience: "audience".into(),
            jwks_uri: "jwks".into(),
        }
    }

    fn credential(provider: SocialProvider, secret: Option<&str>) -> ProviderCredential {
        ProviderCredential {
            provider,
            id_token: "header.payload.signature".into(),
            token_fingerprint: String::new(),
            nonce_preimage: secret.map(str::to_owned),
        }
    }

    fn bound_nonce(app: &str, secret: &str) -> String {
        format!("{app}.{}", URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes())))
    }

    fn binding(provider: SocialProvider, nonce: Option<&str>, secret: Option<&str>) -> Result<()> {
        verify_login_binding(
            &claims(2_000_000_000, nonce, None),
            &credential(provider.clone(), secret),
            &policy(provider),
        )
    }

    #[test]
    fn hash_matches_the_pkce_s256_vector() {
        // RFC 7636 Appendix B: this verifier hashes to this challenge.
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(SECRET.as_bytes())),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        );
    }

    #[test]
    fn token_must_carry_this_app_and_the_login_secret() {
        let nonce = bound_nonce(APP, SECRET);
        assert!(binding(SocialProvider::Google, Some(&nonce), Some(SECRET)).is_ok());

        // Another app's login, for the same user and the same secret.
        let other_app = bound_nonce("9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d", SECRET);
        assert!(binding(SocialProvider::Google, Some(&other_app), Some(SECRET)).is_err());

        // The token without the secret, or with someone else's.
        assert!(binding(SocialProvider::Google, Some(&nonce), None).is_err());
        let other_secret = "M25iVXpKU3puUjFaYWg3T1NDTDQtcW1ROUY5YXlwalNoc0hhakxifmZHag";
        assert!(binding(SocialProvider::Google, Some(&nonce), Some(other_secret)).is_err());

        // A short secret is refused even when it happens to match.
        assert!(binding(SocialProvider::Google, Some(&bound_nonce(APP, "short")), Some("short"))
            .is_err());

        assert!(binding(SocialProvider::Google, None, Some(SECRET)).is_err());
        // The app half alone, or the hash half alone, is not the nonce.
        assert!(binding(SocialProvider::Google, Some(APP), Some(SECRET)).is_err());
        let hash_only = nonce.split_once('.').unwrap().1;
        assert!(binding(SocialProvider::Google, Some(hash_only), Some(SECRET)).is_err());
    }

    #[test]
    fn apple_may_hash_the_nonce_and_google_may_not() {
        let hashed = hex_sha256(bound_nonce(APP, SECRET).as_bytes());
        assert!(binding(SocialProvider::Apple, Some(&hashed), Some(SECRET)).is_ok());
        assert!(binding(SocialProvider::Google, Some(&hashed), Some(SECRET)).is_err());
    }

    #[test]
    fn email_tokens_have_no_nonce_to_bind() {
        assert!(binding(SocialProvider::Email, None, None).is_ok());
    }

    #[test]
    fn email_recovery_accepts_only_firebase_email_authentication() {
        let now = 2_000_000_000;
        let email = claims(now - 60, None, Some("password"));
        assert!(enforce_recent_auth(&email, &SocialProvider::Email, now).is_ok());

        let google = claims(now - 60, None, Some("google.com"));
        assert!(enforce_recent_auth(&google, &SocialProvider::Email, now).is_err());
    }
}

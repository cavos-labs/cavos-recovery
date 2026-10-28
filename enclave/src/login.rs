//! The tokens this enclave issues for email login, and the key that signs them.
//!
//! The key is derived from the root key (`RootKey::login_signing_key`), so it is
//! stable across restarts and exists nowhere but in the enclave. Its public half
//! is published as a JWKS so that anyone can check a token; the enclave itself
//! verifies against the key it holds and never fetches that document back
//! through its untrusted parent.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::DecodingKey;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    SecretKey,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::github::GithubUser;

pub const ISSUER: &str = "https://enclave.cavos.xyz";
pub const AUDIENCE: &str = "cavos-email";
pub const JWKS_URI: &str = "https://enclave.cavos.xyz/.well-known/jwks.json";
pub const GITHUB_ISSUER: &str = "https://enclave.cavos.xyz/github";
pub const GITHUB_AUDIENCE: &str = "cavos-github";
pub const TOKEN_LIFETIME_SECONDS: u64 = 3600;

const SUBJECT_DOMAIN: &str = "cavos-email-subject-v1:";
const GITHUB_SUBJECT_DOMAIN: &str = "cavos-github-subject-v1:";

/// Trim and ASCII-lowercase, the one form of an address used everywhere.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// The stable subject of an email identity: lowercase hex SHA-256 over the
/// domain-separated normalised address.
pub fn subject_id(normalized_email: &str) -> String {
    hex::encode(Sha256::digest(format!("{SUBJECT_DOMAIN}{normalized_email}").as_bytes()))
}

/// The stable subject of a GitHub identity: lowercase hex SHA-256 over the
/// domain-separated OAuth client id and GitHub user id. It differs per OAuth app
/// on purpose, since GitHub reports the same user id to every app.
pub fn github_subject_id(client_id: &str, user_id: u64) -> String {
    hex::encode(Sha256::digest(
        format!("{GITHUB_SUBJECT_DOMAIN}{client_id}:{user_id}").as_bytes(),
    ))
}

pub struct LoginKey {
    signing: SigningKey,
    kid: String,
    x: String,
    y: String,
}

impl LoginKey {
    pub fn new(secret: SecretKey) -> Result<Self> {
        let point = secret.public_key().to_encoded_point(false);
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(point.as_bytes()));
        let x = URL_SAFE_NO_PAD.encode(point.x().context("login key has no x coordinate")?);
        let y = URL_SAFE_NO_PAD.encode(point.y().context("login key has no y coordinate")?);
        Ok(Self { signing: SigningKey::from(secret), kid, x, y })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn decoding_key(&self) -> Result<DecodingKey> {
        DecodingKey::from_ec_components(&self.x, &self.y).context("invalid login key")
    }

    pub fn jwks(&self) -> serde_json::Value {
        json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": self.x,
                "y": self.y,
                "kid": self.kid,
                "alg": "ES256",
                "use": "sig",
            }]
        })
    }

    /// Sign a login token for `email` (already normalised), bound to `nonce`.
    pub fn issue(&self, email: &str, nonce: &str, now: u64) -> Result<String> {
        self.sign(&json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": subject_id(email),
            "email": email,
            "email_verified": true,
            "nonce": nonce,
            "iat": now,
            "auth_time": now,
            "exp": now + TOKEN_LIFETIME_SECONDS,
        }))
    }

    /// Sign a login token for a GitHub `user`, bound to `nonce` and to the OAuth
    /// app (`client_id`) the code was redeemed with.
    pub fn issue_github(
        &self,
        user: &GithubUser,
        client_id: &str,
        nonce: &str,
        now: u64,
    ) -> Result<String> {
        self.sign(&json!({
            "iss": GITHUB_ISSUER,
            "aud": GITHUB_AUDIENCE,
            "sub": github_subject_id(client_id, user.id),
            "azp": client_id,
            "name": user.name.as_deref().unwrap_or(&user.login),
            "preferred_username": user.login,
            "nonce": nonce,
            "iat": now,
            "auth_time": now,
            "exp": now + TOKEN_LIFETIME_SECONDS,
        }))
    }

    fn sign(&self, claims: &serde_json::Value) -> Result<String> {
        let header = json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?),
        );
        let signature: Signature = self.signing.sign(signing_input.as_bytes());
        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())))
    }
}

#[cfg(test)]
pub fn test_key(seed: u8) -> LoginKey {
    use crate::kms::RootKey;
    LoginKey::new(RootKey::for_test([seed; 32]).login_signing_key().unwrap()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_stable_for_a_root_key_and_differs_between_them() {
        assert_eq!(test_key(1).kid(), test_key(1).kid());
        assert_ne!(test_key(1).kid(), test_key(2).kid());
    }

    #[test]
    fn subject_is_domain_separated_hex_sha256() {
        let expected = hex::encode(Sha256::digest(b"cavos-email-subject-v1:user@gmail.com"));
        assert_eq!(subject_id("user@gmail.com"), expected);
        assert_eq!(expected.len(), 64);
    }

    #[test]
    fn normalizes_by_trimming_and_lowercasing() {
        assert_eq!(normalize_email("  User@Gmail.COM \n"), "user@gmail.com");
    }

    #[test]
    fn token_has_the_contract_shape() {
        let key = test_key(7);
        let token = key.issue("user@gmail.com", "app.nonce", 1_790_000_000).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header, json!({ "alg": "ES256", "typ": "JWT", "kid": key.kid() }));
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            claims,
            json!({
                "iss": "https://enclave.cavos.xyz",
                "aud": "cavos-email",
                "sub": subject_id("user@gmail.com"),
                "email": "user@gmail.com",
                "email_verified": true,
                "nonce": "app.nonce",
                "iat": 1_790_000_000u64,
                "auth_time": 1_790_000_000u64,
                "exp": 1_790_003_600u64,
            })
        );
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().len(), 64);
    }

    #[test]
    fn github_subject_is_domain_separated_and_differs_per_app() {
        let expected = hex::encode(Sha256::digest(b"cavos-github-subject-v1:Iv1.abc:583231"));
        assert_eq!(github_subject_id("Iv1.abc", 583231), expected);
        assert_eq!(expected.len(), 64);
        assert_ne!(github_subject_id("Iv1.abc", 583231), github_subject_id("Iv1.xyz", 583231));
        assert_ne!(github_subject_id("Iv1.abc", 583231), github_subject_id("Iv1.abc", 583232));
    }

    #[test]
    fn github_token_has_the_contract_shape() {
        let key = test_key(7);
        let user = GithubUser { id: 583231, login: "octocat".into(), name: None };
        let token = key.issue_github(&user, "Iv1.abc", "app.nonce", 1_790_000_000).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header, json!({ "alg": "ES256", "typ": "JWT", "kid": key.kid() }));
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            claims,
            json!({
                "iss": "https://enclave.cavos.xyz/github",
                "aud": "cavos-github",
                "sub": github_subject_id("Iv1.abc", 583231),
                "azp": "Iv1.abc",
                "name": "octocat",
                "preferred_username": "octocat",
                "nonce": "app.nonce",
                "iat": 1_790_000_000u64,
                "auth_time": 1_790_000_000u64,
                "exp": 1_790_003_600u64,
            })
        );
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().len(), 64);
    }

    #[test]
    fn github_token_prefers_the_display_name() {
        let key = test_key(7);
        let user = GithubUser { id: 1, login: "octocat".into(), name: Some("The Octocat".into()) };
        let token = key.issue_github(&user, "Iv1.abc", "n", 1).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(claims["name"], "The Octocat");
        assert_eq!(claims["preferred_username"], "octocat");
    }

    #[test]
    fn jwks_publishes_the_signing_key() {
        let key = test_key(7);
        let jwks = key.jwks();
        let entry = &jwks["keys"][0];
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
        assert_eq!(entry["kty"], "EC");
        assert_eq!(entry["crv"], "P-256");
        assert_eq!(entry["alg"], "ES256");
        assert_eq!(entry["use"], "sig");
        assert_eq!(entry["kid"], key.kid());
        assert_eq!(URL_SAFE_NO_PAD.decode(entry["x"].as_str().unwrap()).unwrap().len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.decode(entry["y"].as_str().unwrap()).unwrap().len(), 32);
    }
}

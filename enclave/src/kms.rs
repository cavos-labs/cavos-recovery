//! The root sealing key, and the record sealing built on it.
//!
//! # Why a root key rather than per-record KMS calls
//!
//! The previous design sealed every recovery record with a KMS round trip. That
//! put a network call on the critical path of every enrolment and recovery, and
//! made the enclave's KMS integration something that could fail intermittently,
//! in production, per user.
//!
//! Instead the enclave unwraps a single 32-byte root key **once at startup** and
//! derives a fresh per-record key from it. KMS is then never touched again, and
//! the hairy part — decrypting the CMS envelope KMS returns — runs once, at
//! boot, where failure is immediate and loud rather than intermittent.
//!
//! The trade is real and worth stating: the root key lives in enclave memory for
//! the process's lifetime, so an attacker who breaks the enclave gets every
//! record rather than one. But an attacker who breaks the enclave also has its
//! KMS authority and could decrypt each record on demand anyway, so the two
//! designs end up in much the same place.
//!
//! # Why the parent cannot use these credentials
//!
//! The enclave has no network and no instance role, so the AWS credentials it
//! signs with are handed to it by the parent — which is untrusted. That is safe
//! because the KMS key policy requires
//! `kms:RecipientAttestation:PCR0` to equal this enclave image's measurement.
//! The parent holds the same credentials and still cannot decrypt: it cannot
//! produce an attestation document, and KMS will not release the key without
//! one. Credentials alone are not authority here — the measurement is.

use anyhow::{anyhow, bail, Context, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use openssl::cms::CmsContentInfo;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::nsm::Nsm;

/// KMS speaks standard base64 with padding, while the browser-facing channel
/// protocol uses base64url without it (`crypto::b64`). Mixing the two is not a
/// cosmetic difference: KMS answers a base64url attestation document with a
/// bare `SerializationException`, which says nothing about the cause. These
/// helpers exist so the distinction is visible at the call site.
fn kms_b64(bytes: impl AsRef<[u8]>) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(bytes)
}

fn kms_unb64(value: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.decode(value).context("invalid base64 from KMS")
}

/// Domain separator for per-record keys derived from the root key.
const RECORD_SEAL_INFO: &[u8] = b"cavos-record-seal-v1";
/// Bytes of random salt stored alongside each sealed record.
const SEAL_SALT_LEN: usize = 32;
/// AES-GCM nonce length.
const SEAL_NONCE_LEN: usize = 12;

/// The enclave's long-lived sealing key. Never leaves the enclave, never logged.
pub struct RootKey(Zeroizing<[u8; 32]>);

pub struct KmsConfig {
    pub region: String,
    /// The KMS-wrapped root key. Ciphertext, so it is safe to pass through the
    /// untrusted parent as an environment variable.
    pub wrapped_root_key_b64: String,
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<String>,
}

#[derive(Deserialize)]
struct DecryptResponse {
    #[serde(rename = "CiphertextForRecipient")]
    ciphertext_for_recipient: Option<String>,
}

/// Unwrap the root key by asking KMS to decrypt it *to this enclave*.
///
/// The RSA key generated here exists only for this call. Its public half goes
/// into an attestation document, KMS encrypts the plaintext to it, and the
/// private half — which never left the enclave — opens the result. That is what
/// makes the answer readable by this enclave and by nothing else.
pub async fn unwrap_root_key(nsm: &Nsm, http: &Client, config: &KmsConfig) -> Result<RootKey> {
    let rsa = Rsa::generate(2048).context("could not generate the KMS recipient key")?;
    let private = PKey::from_rsa(rsa).context("could not wrap the recipient key")?;
    let public_der = private
        .public_key_to_der()
        .context("could not encode the recipient public key")?;

    let attestation = nsm
        .attest_for_kms(&public_der)
        .context("could not attest for KMS")?;

    let body = json!({
        "CiphertextBlob": config.wrapped_root_key_b64,
        "Recipient": {
            "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            "AttestationDocument": kms_b64(&attestation),
        }
    })
    .to_string();

    let host = format!("kms.{}.amazonaws.com", config.region);
    let signed = sigv4::sign(
        &sigv4::Request {
            method: "POST",
            host: &host,
            path: "/",
            target: "TrentService.Decrypt",
            body: body.as_bytes(),
            region: &config.region,
            service: "kms",
            access_key_id: &config.access_key_id,
            secret_access_key: &config.secret_access_key,
            session_token: config.session_token.as_deref(),
        },
        sigv4::now(),
    )?;

    let mut request = http
        .post(format!("https://{host}/"))
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amz-target", "TrentService.Decrypt")
        .header("x-amz-date", &signed.amz_date)
        .header("authorization", &signed.authorization);
    if let Some(token) = config.session_token.as_deref() {
        request = request.header("x-amz-security-token", token);
    }

    let response = request
        .body(body)
        .send()
        .await
        .context("KMS Decrypt request failed")?;
    if !response.status().is_success() {
        // The body may name the key and the condition that failed, which is
        // operationally useful and contains no user secret.
        bail!(
            "KMS Decrypt rejected ({}): {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }

    let envelope = response
        .json::<DecryptResponse>()
        .await
        .context("malformed KMS response")?
        .ciphertext_for_recipient
        .ok_or_else(|| anyhow!("KMS did not envelope the response — was Recipient sent?"))?;

    let plaintext = decrypt_cms(&kms_unb64(&envelope)?, &private)?;
    let bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("the root key must be 32 bytes, got {}", plaintext.len()))?;
    Ok(RootKey(Zeroizing::new(bytes)))
}

/// Decrypt the CMS EnvelopedData that KMS returns in `CiphertextForRecipient`.
///
/// OpenSSL is used here in preference to the pure-Rust `cms` and `rsa` crates,
/// which are both still pre-release. There is no certificate in play — KMS
/// enveloped to a bare public key — so the recipient-matching check has to be
/// skipped; the private key either opens the envelope or it does not.
fn decrypt_cms(envelope: &[u8], private: &PKey<openssl::pkey::Private>) -> Result<Zeroizing<Vec<u8>>> {
    let cms = CmsContentInfo::from_der(envelope).context("malformed CMS envelope from KMS")?;
    let plaintext = cms
        .decrypt_without_cert_check(private)
        .context("could not open the CMS envelope from KMS")?;
    Ok(Zeroizing::new(plaintext))
}

impl RootKey {
    /// Seal a record. Layout: `salt ‖ nonce ‖ ciphertext`.
    ///
    /// Each record gets its own random salt, so every record is encrypted under
    /// a distinct derived key without the enclave needing to know which wallet
    /// the record belongs to — which it cannot know at unseal time, since the
    /// identity only becomes readable after decryption.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use rand_core::{OsRng, RngCore};

        let mut salt = [0u8; SEAL_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; SEAL_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let key = self.derive(&salt)?;
        let ciphertext = Aes256Gcm::new_from_slice(key.as_slice())
            .expect("AES key size")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: plaintext, aad: &salt },
            )
            .map_err(|_| anyhow!("record sealing failed"))?;

        let mut out = Vec::with_capacity(SEAL_SALT_LEN + SEAL_NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        if sealed.len() <= SEAL_SALT_LEN + SEAL_NONCE_LEN {
            bail!("sealed record is truncated");
        }
        let (salt, rest) = sealed.split_at(SEAL_SALT_LEN);
        let (nonce, ciphertext) = rest.split_at(SEAL_NONCE_LEN);

        let key = self.derive(salt)?;
        let plaintext = Aes256Gcm::new_from_slice(key.as_slice())
            .expect("AES key size")
            .decrypt(
                Nonce::from_slice(nonce),
                Payload { msg: ciphertext, aad: salt },
            )
            .map_err(|_| anyhow!("sealed record failed authentication"))?;
        Ok(Zeroizing::new(plaintext))
    }

    fn derive(&self, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(salt), self.0.as_slice())
            .expand(RECORD_SEAL_INFO, key.as_mut_slice())
            .map_err(|_| anyhow!("record key derivation failed"))?;
        Ok(key)
    }

    #[cfg(test)]
    pub fn for_test(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// A minimal AWS Signature Version 4 signer.
///
/// Hand-written rather than pulled from `aws-sigv4` because that crate brings
/// eight Smithy runtime crates with it, and everything linked into this binary
/// is measured into PCR0 and has to be auditable. The algorithm is fully
/// specified and covered below by AWS's own published test vector.
mod sigv4 {
    use super::*;

    type HmacSha256 = Hmac<Sha256>;

    pub struct Request<'a> {
        pub method: &'a str,
        pub host: &'a str,
        pub path: &'a str,
        pub target: &'a str,
        pub body: &'a [u8],
        pub region: &'a str,
        pub service: &'a str,
        pub access_key_id: &'a str,
        pub secret_access_key: &'a str,
        pub session_token: Option<&'a str>,
    }

    pub struct Signed {
        pub authorization: String,
        pub amz_date: String,
    }

    /// `YYYYMMDDTHHMMSSZ`, the only timestamp format SigV4 accepts.
    pub fn now() -> String {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before the unix epoch")
            .as_secs();
        format_amz_date(seconds)
    }

    /// Civil-time conversion from a unix timestamp, so the signer does not need
    /// a date library. Uses the standard days-from-civil algorithm.
    fn format_amz_date(seconds: u64) -> String {
        let days = (seconds / 86_400) as i64;
        let time_of_day = seconds % 86_400;

        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let day_of_era = z.rem_euclid(146_097);
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let mp = (5 * day_of_year + 2) / 153;
        let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let year = if month <= 2 { year + 1 } else { year };

        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            year,
            month,
            day,
            time_of_day / 3_600,
            (time_of_day % 3_600) / 60,
            time_of_day % 60
        )
    }

    pub fn sign(request: &Request<'_>, amz_date: String) -> Result<Signed> {
        let date = &amz_date[..8];
        let payload_hash = hex::encode(Sha256::digest(request.body));

        // Signed headers must be sorted by lowercase name, and the canonical
        // form of each value is trimmed. KMS requires host, x-amz-date and
        // x-amz-target to be signed; the security token joins them when the
        // credentials are temporary, which they always are here.
        let mut headers: Vec<(String, String)> = vec![
            ("content-type".into(), "application/x-amz-json-1.1".into()),
            ("host".into(), request.host.to_string()),
            ("x-amz-date".into(), amz_date.clone()),
            ("x-amz-target".into(), request.target.to_string()),
        ];
        if let Some(token) = request.session_token {
            headers.push(("x-amz-security-token".into(), token.to_string()));
        }
        headers.sort_by(|a, b| a.0.cmp(&b.0));

        let canonical_headers = headers
            .iter()
            .map(|(name, value)| format!("{name}:{}\n", value.trim()))
            .collect::<String>();
        let signed_headers = headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(";");

        let canonical_request = format!(
            "{}\n{}\n\n{}\n{}\n{}",
            request.method, request.path, canonical_headers, signed_headers, payload_hash
        );

        let scope = format!("{date}/{}/{}/aws4_request", request.region, request.service);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        let signing_key = signing_key(request.secret_access_key, date, request.region, request.service)?;
        let signature = hex::encode(hmac(&signing_key, string_to_sign.as_bytes())?);

        Ok(Signed {
            authorization: format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
                request.access_key_id
            ),
            amz_date,
        })
    }

    pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Result<Vec<u8>> {
        let step = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes())?;
        let step = hmac(&step, region.as_bytes())?;
        let step = hmac(&step, service.as_bytes())?;
        hmac(&step, b"aws4_request")
    }

    fn hmac(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let mut mac =
            HmacSha256::new_from_slice(key).map_err(|_| anyhow!("invalid HMAC key length"))?;
        mac.update(message);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// AWS's published worked example for deriving a signing key.
        /// https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
        #[test]
        fn derives_aws_published_signing_key() {
            let key = signing_key(
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                "20150830",
                "us-east-1",
                "iam",
            )
            .unwrap();
            assert_eq!(
                hex::encode(key),
                "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
            );
        }

        #[test]
        fn formats_amz_dates() {
            // 2015-08-30T12:36:00Z, the instant from the AWS example.
            assert_eq!(format_amz_date(1_440_938_160), "20150830T123600Z");
            assert_eq!(format_amz_date(0), "19700101T000000Z");
            // A leap day, to exercise the civil-date arithmetic.
            assert_eq!(format_amz_date(1_709_208_000), "20240229T120000Z");
        }

        #[test]
        fn signs_with_a_stable_authorization_header() {
            let signed = sign(
                &Request {
                    method: "POST",
                    host: "kms.us-east-1.amazonaws.com",
                    path: "/",
                    target: "TrentService.Decrypt",
                    body: b"{}",
                    region: "us-east-1",
                    service: "kms",
                    access_key_id: "AKIDEXAMPLE",
                    secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                    session_token: Some("token"),
                },
                "20150830T123600Z".to_string(),
            )
            .unwrap();

            assert!(signed.authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/kms/aws4_request"));
            // The security token must be signed when present, or KMS rejects it.
            assert!(signed
                .authorization
                .contains("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_unseals() {
        let root = RootKey::for_test([7u8; 32]);
        let sealed = root.seal(b"recovery record").unwrap();
        assert_eq!(&*root.unseal(&sealed).unwrap(), b"recovery record");
    }

    #[test]
    fn every_sealing_is_distinct() {
        let root = RootKey::for_test([7u8; 32]);
        let first = root.seal(b"same plaintext").unwrap();
        let second = root.seal(b"same plaintext").unwrap();
        assert_ne!(first, second, "a fresh salt and nonce each time");
    }

    #[test]
    fn rejects_a_record_sealed_under_another_root() {
        let sealed = RootKey::for_test([7u8; 32]).seal(b"secret").unwrap();
        assert!(RootKey::for_test([8u8; 32]).unseal(&sealed).is_err());
    }

    #[test]
    fn rejects_tampering() {
        let root = RootKey::for_test([7u8; 32]);
        let mut sealed = root.seal(b"secret").unwrap();

        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(root.unseal(&sealed).is_err(), "ciphertext is authenticated");

        let mut salt_tampered = root.seal(b"secret").unwrap();
        salt_tampered[0] ^= 0x01;
        assert!(
            root.unseal(&salt_tampered).is_err(),
            "the salt is bound as AAD, so swapping it fails rather than deriving a wrong key silently"
        );
    }

    #[test]
    fn rejects_truncated_records() {
        let root = RootKey::for_test([7u8; 32]);
        assert!(root.unseal(&[0u8; SEAL_SALT_LEN + SEAL_NONCE_LEN]).is_err());
        assert!(root.unseal(b"short").is_err());
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SocialProvider {
    Google,
    Apple,
    Email,
    Github,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCredential {
    pub provider: SocialProvider,
    /// Raw OIDC ID token. It reaches this workload only inside the P-256
    /// application-layer encrypted channel.
    pub id_token: String,
    /// Base64url SHA-256 of `id_token`. The control plane stores only a second
    /// SHA-256 of this value to enforce single use.
    pub token_fingerprint: String,
    /// The secret whose hash the client sent as the login `nonce`. It never
    /// leaves the client except inside this encrypted job, so holding the token
    /// alone is not enough to use it. Required for every provider.
    #[serde(default)]
    pub nonce_preimage: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    pub app_id: String,
    pub environment_id: String,
    pub provider: SocialProvider,
    pub issuer: String,
    pub audience: String,
    pub jwks_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum WorkloadJob {
    Enroll {
        credential: ProviderCredential,
        policy: RecoveryPolicy,
        /// Present only for Stellar classic accounts. This is the random DEK
        /// which encrypts the Stellar control seed; the control seed itself is
        /// never sent to or stored by the enclave.
        stellar_dek_b64: Option<String>,
    },
    Recover {
        credential: ProviderCredential,
        sealed_record_b64: String,
        authorizations: Vec<ChainAuthorization>,
        stellar_recipient_pubkey_b64: Option<String>,
    },
    /// Ask what an existing sealed record holds, without changing anything.
    ///
    /// The control plane stores the record and could otherwise answer this
    /// itself. A client resuming an enrolment, or checking that it is still
    /// protected, must hear it from the enclave instead.
    Confirm {
        credential: ProviderCredential,
        sealed_record_b64: String,
        /// The DEK this device holds, when the record is expected to seal one.
        stellar_dek_b64: Option<String>,
    },
    /// Trade the code the enclave mailed for a token signed by the enclave.
    VerifyEmail {
        email: String,
        code: String,
        client_nonce: String,
    },
    /// Trade a GitHub authorization code for a token signed by the enclave.
    VerifyGithub {
        code_verifier: String,
        client_nonce: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "chain", rename_all = "snake_case")]
pub enum ChainAuthorization {
    Starknet {
        chain_id_hex: String,
        account_hex: String,
        new_x_hex: String,
        new_y_hex: String,
        recovery_nonce: String,
        expires_at: u64,
    },
    Solana {
        account_b58_bytes_b64: String,
        new_pubkey_b64: String,
        /// Decimal string to avoid precision loss in browser JSON runtimes.
        recovery_nonce: String,
        expires_at: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedRecoveryRecord {
    pub version: u8,
    pub policy: RecoveryPolicy,
    pub identity_commitment_hex: String,
    pub recovery_private_key_b64: String,
    pub stellar_dek_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum WorkloadResult {
    Enrolled {
        sealed_record_b64: String,
        identity_commitment_hex: String,
        policy_hash_hex: String,
        recovery_pubkey_compressed_b64: String,
        recovery_x_hex: String,
        recovery_y_hex: String,
    },
    Recovered {
        identity_commitment_hex: String,
        authorizations: Vec<SignedAuthorization>,
        stellar_device_wrap_b64: Option<String>,
    },
    /// The record belongs to the credential's identity and holds this authority.
    Confirmed {
        identity_commitment_hex: String,
        policy_hash_hex: String,
        recovery_pubkey_compressed_b64: String,
        recovery_x_hex: String,
        recovery_y_hex: String,
        /// Whether the record seals the DEK the client sent. Absent when the
        /// client sent none.
        dek_matches: Option<bool>,
    },
    EmailVerified {
        id_token: String,
    },
    GithubVerified {
        id_token: String,
    },
}

/// What the control plane supplies to redeem a GitHub authorization code. It
/// is untrusted input: the client's `code_verifier`, which arrives inside the
/// encrypted job, is what stops anyone but the client redeeming the code.
#[derive(Clone, Serialize, Deserialize)]
pub struct GithubGrant {
    pub code: String,
    pub app_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

impl std::fmt::Debug for GithubGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubGrant")
            .field("code", &"<redacted>")
            .field("app_id", &self.app_id)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "chain", rename_all = "snake_case")]
pub enum SignedAuthorization {
    Starknet {
        digest_hex: String,
        r_hex: String,
        s_hex: String,
        y_parity: bool,
        recovery_nonce: String,
        expires_at: u64,
    },
    Solana {
        message_b64: String,
        signature_b64: String,
        recovery_pubkey_compressed_b64: String,
        recovery_nonce: String,
        expires_at: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedJob {
    pub client_public_key_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedResult {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

/// The runtime configuration the enclave fetches from its parent at startup.
///
/// It cannot come from the environment: `nitro-cli run-enclave` has no way to
/// set one, and baking values into the image would change PCR0 every time a
/// credential rotated. So the enclave asks the parent for it over vsock.
///
/// The parent is untrusted, and supplying this does not make it trusted:
///
///   * `wrapped_root_key` is ciphertext under a KMS key the parent cannot
///     encrypt to (its role has no `kms:Encrypt`), so it cannot substitute a
///     root key of its own — and even if it could, that would let it seal new
///     records, never read existing ones;
///   * the credentials are the parent's own, and are not authority by
///     themselves: the key policy releases the root key only against an
///     attestation the parent cannot produce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveConfig {
    pub region: String,
    pub wrapped_root_key_b64: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    /// Absent when the host has no mail identity; sending codes is then refused
    /// and everything else is unaffected.
    #[serde(default)]
    pub mail: Option<MailConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailConfig {
    pub from: String,
    pub sender: String,
    pub helo: String,
    pub dkim_selector: String,
    pub dkim_private_key_pem: String,
}

/// A request arriving over vsock from the parent instance.
///
/// The parent is an untrusted relay: it can drop, reorder, or forge these
/// messages, but it cannot read the credential inside `RunJob` (encrypted to
/// the session's channel key) nor forge an attestation document. Every field
/// here is therefore treated as hostile input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum EnclaveRequest {
    /// Open a channel for `session_id` and attest to its public key.
    OpenSession { session_id: String },
    /// Run one job inside an already-opened session.
    RunJob {
        session_id: String,
        job: EncryptedJob,
        /// Base64url SHA-256 of the ID token, bound by the control plane to
        /// enforce single use. The enclave checks the credential matches it.
        /// Not used by `verify_email`, which has no credential yet.
        #[serde(default)]
        auth_challenge_hash: String,
        /// Supplied by the control plane, which bound the code to the app. Only
        /// `verify_github` uses it.
        #[serde(default)]
        github: Option<GithubGrant>,
    },
    /// Generate a one-time code and mail it to `email`.
    SendCode {
        email: String,
        app_id: String,
        app_name: String,
    },
    /// The public keys that verify tokens this enclave issues.
    LoginKeys,
    /// Liveness probe for the parent's health check. Reveals nothing.
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum EnclaveResponse {
    SessionOpened {
        /// Uncompressed SEC1 P-256 channel key. The browser must take this key
        /// from the attestation document rather than from here; it is repeated
        /// in the clear only so the control plane can relay it without parsing
        /// CBOR.
        ephemeral_public_key_b64: String,
        /// COSE_Sign1 attestation document. Its `public_key` field carries the
        /// same channel key and its `user_data` binds it to the session.
        attestation_document_b64: String,
    },
    JobCompleted {
        /// For the control plane, which persists parts of it. It is relayed in
        /// the clear and so proves nothing to the client.
        result: WorkloadResult,
        /// The same result sealed under the session's response key. This is the
        /// copy the client acts on.
        sealed_result: SealedResult,
    },
    Pong,
    CodeSent,
    LoginKeys {
        jwks: serde_json::Value,
    },
    /// A failure the parent may surface. Messages are deliberately coarse: a
    /// detailed reason would leak facts about a user's credential to the
    /// untrusted relay.
    Error {
        code: String,
    },
}

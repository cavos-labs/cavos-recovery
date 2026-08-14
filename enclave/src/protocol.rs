use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SocialProvider {
    Google,
    Apple,
    Email,
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
        auth_challenge_hash: String,
    },
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
        result: WorkloadResult,
    },
    Pong,
    /// A failure the parent may surface. Messages are deliberately coarse: a
    /// detailed reason would leak facts about a user's credential to the
    /// untrusted relay.
    Error {
        code: String,
    },
}

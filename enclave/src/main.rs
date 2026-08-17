//! The Cavos confidential recovery workload, as a long-lived Nitro enclave.
//!
//! It used to be a one-shot program: one Confidential Space VM per session,
//! booted on demand, polling a control plane for its single job. Booting that VM
//! took 49–134 seconds for roughly two seconds of work, and failed outright
//! about nine percent of the time on zone capacity. This version is a server: it
//! starts once, and answers requests over vsock in milliseconds.
//!
//! # Trust
//!
//! The parent EC2 instance is a relay and is **not trusted**. It can drop,
//! reorder, replay, or invent requests. What it cannot do is read a user's
//! credential — that is encrypted in the browser to a P-256 key this enclave
//! generated and attested to — or forge an attestation document, which is what
//! convinces the browser the key belongs to this exact enclave image. Every
//! request below is therefore treated as hostile input.
//!
//! # Shape
//!
//!   OpenSession → generate a channel key, attest to it, hand back the document
//!   RunJob      → decrypt the job with that session's key, verify the OIDC
//!                 credential, then sign or seal
//!
//! Sessions are single-use: `RunJob` removes the channel key, so a replayed job
//! finds nothing.

mod crypto;
mod failure;
mod kms;
mod nsm;
mod oidc;
mod outbound;
mod protocol;
mod sessions;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use p256::{ecdsa::SigningKey, SecretKey};
use protocol::{
    EnclaveConfig, EnclaveRequest, EnclaveResponse, EncryptedJob, SealedRecoveryRecord, WorkloadJob,
    WorkloadResult,
};
use reqwest::Client;
use tokio::sync::Mutex;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use zeroize::Zeroizing;

use kms::RootKey;
use outbound::ProxiedHost;
use sessions::{SessionError, SessionStore};

/// vsock port the parent connects to.
const SERVICE_PORT: u32 = 5005;

/// Ceiling on a single request frame. Generous for a job carrying an ID token
/// and a handful of authorizations, and far below anything that would strain
/// the enclave's memory.
const MAX_FRAME_BYTES: u32 = 256 * 1024;

/// Where the parent's `vsock-proxy` listens for each host the enclave may
/// reach. Fixed at build time, so the set is measured into PCR0: a parent that
/// wants the enclave talking to somewhere else must change the image, which
/// changes the measurement, which the browser rejects.
const KMS_HOST: ProxiedHost =
    ProxiedHost { hostname: "kms", vsock_port: 8000, local_port: 8000 };
const OIDC_HOST: ProxiedHost =
    ProxiedHost { hostname: "oidc", vsock_port: 8001, local_port: 8001 };

/// vsock port on the parent that serves the enclave's runtime configuration.
/// The relay binds it before the enclave starts.
const CONFIG_PORT: u32 = 5006;

/// Fetch the runtime configuration from the parent.
///
/// This exists because `nitro-cli run-enclave` cannot set environment
/// variables — the enclave's ENV is fixed at image build time, and baking in a
/// rotating credential or the wrapped root key would change PCR0 on every
/// rotation. See `protocol::EnclaveConfig` for why taking it from an untrusted
/// parent is safe.
async fn fetch_config() -> Result<EnclaveConfig> {
    let mut stream = VsockStream::connect(VsockAddr::new(outbound::PARENT_CID, CONFIG_PORT))
        .await
        .context("parent config service unavailable")?;
    outbound::write_frame(&mut stream, b"config").await?;
    let frame = outbound::read_frame(&mut stream, MAX_FRAME_BYTES).await?;
    serde_json::from_slice(&frame).context("malformed configuration from the parent")
}

/// Everything a request handler needs, shared across connections.
struct Enclave {
    nsm: nsm::Nsm,
    root: RootKey,
    http: Client,
    sessions: Mutex<SessionStore>,
}

/// vsock port the parent listens on for startup diagnostics.
const LOG_PORT: u32 = 5007;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        // Never print credentials, decrypted jobs, keys, or sealed blobs.
        let message = format!("confidential recovery enclave failed to start: {error:#}");
        eprintln!("{message}");
        // An enclave's stdout is invisible unless it was launched in debug
        // mode, and debug mode zeroes the PCRs — so the one configuration in
        // which the enclave can explain itself is also the one in which KMS
        // will refuse to talk to it. Reporting the failure to the parent is
        // what makes a production enclave diagnosable at all.
        //
        // This is a message the parent could already infer (the enclave died),
        // and it is written by the same code the browser attests, so it cannot
        // be used to leak secrets unless this file is changed — which changes
        // the measurement.
        report_startup_failure(&message).await;
        std::process::exit(1);
    }
}

async fn report_startup_failure(message: &str) {
    let attempt = async {
        let mut stream = VsockStream::connect(VsockAddr::new(outbound::PARENT_CID, LOG_PORT))
            .await
            .ok()?;
        outbound::write_frame(&mut stream, message.as_bytes()).await.ok()
    };
    // Best effort: if the parent is not listening there is nothing more to do,
    // and the exit code still tells systemd the enclave failed.
    let _ = tokio::time::timeout(Duration::from_secs(5), attempt).await;
}

async fn run() -> Result<()> {
    // Networking first: both the config fetch and the KMS call below need it.
    outbound::bring_up_loopback().context("could not bring up loopback")?;
    outbound::start_forwarder(KMS_HOST).await?;
    outbound::start_forwarder(OIDC_HOST).await?;

    let config = fetch_config().await.context("could not read configuration")?;
    let http = build_http_client()?;
    let nsm = nsm::Nsm::open()?;

    // The single KMS call of this process's lifetime. Failing here is fatal by
    // design: an enclave that cannot unseal records must refuse to serve rather
    // than accept traffic and fail per user.
    let root = kms::unwrap_root_key(
        &nsm,
        &http,
        &kms::KmsConfig {
            region: config.region.clone(),
            wrapped_root_key_b64: config.wrapped_root_key_b64.clone(),
            access_key_id: config.access_key_id.clone(),
            secret_access_key: Zeroizing::new(config.secret_access_key.clone()),
            session_token: config.session_token.clone(),
        },
    )
    .await
    .context("could not unwrap the root sealing key")?;

    let enclave = Arc::new(Enclave {
        nsm,
        root,
        http,
        sessions: Mutex::new(SessionStore::new()),
    });

    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, SERVICE_PORT))
        .context("could not bind the vsock service port")?;
    eprintln!("[enclave] ready on vsock port {SERVICE_PORT}");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("[enclave] accept failed: {error}");
                continue;
            }
        };
        let enclave = Arc::clone(&enclave);
        tokio::spawn(async move {
            if let Err(error) = serve(enclave, stream).await {
                eprintln!("[enclave] connection ended: {error}");
            }
        });
    }
}

/// Point `reqwest` at the loopback forwarders while leaving SNI, the `Host`
/// header, and certificate validation aimed at the real hostnames. The parent
/// relays bytes it cannot read, and cannot present a valid certificate for a
/// host it is not.
fn build_http_client() -> Result<Client> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let local = |port| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let oidc = local(OIDC_HOST.local_port);

    Client::builder()
        .timeout(Duration::from_secs(20))
        // The provider JWKS endpoints an ID token may be verified against.
        .resolve("accounts.google.com", oidc)
        .resolve("www.googleapis.com", oidc)
        .resolve("appleid.apple.com", oidc)
        .resolve("securetoken.google.com", oidc)
        // Regional KMS endpoints all resolve through the same proxy; the exact
        // host is set by the configured region at call time.
        .resolve("kms.us-east-1.amazonaws.com", local(KMS_HOST.local_port))
        .build()
        .context("could not build the enclave HTTP client")
}

async fn serve<S>(enclave: Arc<Enclave>, mut stream: S) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let frame = outbound::read_frame(&mut stream, MAX_FRAME_BYTES).await?;
    let request: EnclaveRequest =
        serde_json::from_slice(&frame).context("malformed request from the parent")?;

    let response = match handle(&enclave, request).await {
        Ok(response) => response,
        Err(error) => {
            // Log the detail inside the enclave; return only a coarse code, so
            // the untrusted relay learns nothing about why a credential failed.
            eprintln!("[enclave] request failed: {error:#}");
            // The detail stays inside; the class goes out. It names which check
            // refused the request, never the value that failed it. See
            // `failure` for why that distinction is the whole design.
            EnclaveResponse::Error { code: failure::classify(&error).into() }
        }
    };

    outbound::write_frame(&mut stream, &serde_json::to_vec(&response)?).await
}

async fn handle(enclave: &Enclave, request: EnclaveRequest) -> Result<EnclaveResponse> {
    match request {
        EnclaveRequest::Ping => Ok(EnclaveResponse::Pong),

        EnclaveRequest::OpenSession { session_id } => {
            validate_session_id(&session_id)?;
            let public_key = {
                let mut sessions = enclave.sessions.lock().await;
                sessions
                    .open(&session_id, Instant::now())
                    .map_err(|error| match error {
                        SessionError::AtCapacity => anyhow!("session store is at capacity"),
                        SessionError::Unknown => anyhow!("session could not be opened"),
                    })?
            };
            let document = enclave.nsm.attest_session(&public_key, &session_id)?;
            Ok(EnclaveResponse::SessionOpened {
                ephemeral_public_key_b64: crypto::b64(&public_key),
                attestation_document_b64: crypto::b64(&document),
            })
        }

        EnclaveRequest::RunJob { session_id, job, auth_challenge_hash } => {
            validate_session_id(&session_id)?;
            // Claiming removes the session, so this job cannot be replayed.
            let channel = {
                let mut sessions = enclave.sessions.lock().await;
                sessions
                    .claim(&session_id, Instant::now())
                    .map_err(|_| anyhow!("unknown, expired, or already-used session"))
                    .context(failure::Failure::SessionUnknown)?
            };
            let plaintext = decrypt_job(&channel, &session_id, job)?;
            let job: WorkloadJob =
                serde_json::from_slice(&plaintext).context("invalid recovery job")?;
            let result = process_job(enclave, job, &auth_challenge_hash).await?;
            Ok(EnclaveResponse::JobCompleted { result })
        }
    }
}

/// Session ids come from the parent and end up bound into an attestation
/// document, so they are constrained rather than trusted.
fn validate_session_id(session_id: &str) -> Result<()> {
    if session_id.is_empty() || session_id.len() > 64 {
        bail!("session id has an implausible length");
    }
    if !session_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("session id contains unexpected characters");
    }
    Ok(())
}

fn decrypt_job(
    channel: &crypto::ChannelKey,
    session_id: &str,
    job: EncryptedJob,
) -> Result<Zeroizing<Vec<u8>>> {
    channel.decrypt(
        &crypto::unb64(&job.client_public_key_b64)?,
        &crypto::unb64(&job.nonce_b64)?,
        &crypto::unb64(&job.ciphertext_b64)?,
        session_id,
    )
}

async fn process_job(
    enclave: &Enclave,
    job: WorkloadJob,
    auth_challenge_hash: &str,
) -> Result<WorkloadResult> {
    match job {
        WorkloadJob::Enroll { credential, policy, stellar_dek_b64 } => {
            if credential.provider != policy.provider {
                return Err(anyhow!("credential provider does not match policy")
                    .context(failure::Failure::ProviderMismatch));
            }
            let claims =
                oidc::verify_id_token(&enclave.http, &credential, &policy, auth_challenge_hash)
                    .await?;
            let identity = crypto::identity_commitment(&policy, &claims.sub);
            let policy_digest = crypto::policy_hash(&policy);
            let recovery_key = crypto::generate_recovery_key();
            let (compressed, x, y) = crypto::recovery_public_parts(&recovery_key);

            let stellar_dek = stellar_dek_b64.map(|value| crypto::unb64(&value)).transpose()?;
            if stellar_dek.as_ref().is_some_and(|dek| dek.len() != 32) {
                bail!("Stellar DEK must be 32 bytes");
            }

            let record = SealedRecoveryRecord {
                version: 1,
                policy,
                identity_commitment_hex: crypto::hex(&identity),
                recovery_private_key_b64: crypto::b64(recovery_key.to_bytes()),
                stellar_dek_b64: stellar_dek.map(crypto::b64),
            };
            let serialized = Zeroizing::new(serde_json::to_vec(&record)?);
            let sealed = enclave.root.seal(&serialized)?;

            Ok(WorkloadResult::Enrolled {
                sealed_record_b64: crypto::b64(sealed),
                identity_commitment_hex: crypto::hex(&identity),
                policy_hash_hex: crypto::hex(&policy_digest),
                recovery_pubkey_compressed_b64: crypto::b64(compressed),
                recovery_x_hex: crypto::hex(&x),
                recovery_y_hex: crypto::hex(&y),
            })
        }

        WorkloadJob::Recover {
            credential,
            sealed_record_b64,
            authorizations,
            stellar_recipient_pubkey_b64,
        } => {
            let record_bytes = enclave.root.unseal(&crypto::unb64(&sealed_record_b64)?)?;
            let record: SealedRecoveryRecord =
                serde_json::from_slice(&record_bytes).context("invalid sealed recovery record")?;
            if record.version != 1 || credential.provider != record.policy.provider {
                return Err(anyhow!("sealed recovery policy mismatch")
                    .context(failure::Failure::ProviderMismatch));
            }

            let claims = oidc::verify_id_token(
                &enclave.http,
                &credential,
                &record.policy,
                auth_challenge_hash,
            )
            .await?;
            let identity = crypto::identity_commitment(&record.policy, &claims.sub);
            if crypto::hex(&identity) != record.identity_commitment_hex {
                bail!("social identity does not match enrolled identity");
            }

            let secret_bytes = Zeroizing::new(crypto::unb64(&record.recovery_private_key_b64)?);
            let secret = SecretKey::from_slice(&secret_bytes)
                .context("invalid sealed recovery private key")?;
            let signing_key = SigningKey::from(secret);

            let mut signed = Vec::with_capacity(authorizations.len());
            for authorization in &authorizations {
                signed.push(crypto::sign_authorization(&signing_key, authorization)?);
            }

            let stellar_device_wrap_b64 =
                match (record.stellar_dek_b64, stellar_recipient_pubkey_b64) {
                    (Some(dek), Some(recipient)) => Some(crypto::b64(crypto::stellar_wrap(
                        &crypto::unb64(&dek)?,
                        &crypto::unb64(&recipient)?,
                    )?)),
                    (None, None) => None,
                    _ => bail!("Stellar recovery inputs are incomplete"),
                };

            Ok(WorkloadResult::Recovered {
                identity_commitment_hex: crypto::hex(&identity),
                authorizations: signed,
                stellar_device_wrap_b64,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_session_id;

    #[test]
    fn accepts_uuid_shaped_session_ids() {
        assert!(validate_session_id("0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f").is_ok());
    }

    #[test]
    fn rejects_implausible_session_ids() {
        assert!(validate_session_id("").is_err());
        assert!(validate_session_id(&"a".repeat(65)).is_err());
        assert!(validate_session_id("../../etc/passwd").is_err());
        assert!(validate_session_id("has space").is_err());
        assert!(validate_session_id("nul\0byte").is_err());
    }
}

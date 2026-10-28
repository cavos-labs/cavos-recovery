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

mod codes;
mod crypto;
mod failure;
mod github;
mod kms;
mod login;
mod mail;
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
    EnclaveConfig, EnclaveRequest, EnclaveResponse, EncryptedJob, GithubGrant, MailConfig,
    ProviderCredential, SealedRecoveryRecord, SealedResult, WorkloadJob, WorkloadResult,
};
use reqwest::Client;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use zeroize::Zeroizing;

use codes::{CodeError, CodeStore};
use kms::RootKey;
use login::LoginKey;
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
    login: LoginKey,
    mail_origin: Option<mail::Origin>,
    mail_http: Client,
    sessions: Mutex<SessionStore>,
    codes: Mutex<CodeStore>,
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

    let login = LoginKey::new(root.login_signing_key()?)?;
    let mail_origin = config.mail.as_ref().map(build_mail_origin).transpose()?;
    let mail_http = build_mail_http_client()?;

    let enclave = Arc::new(Enclave {
        nsm,
        root,
        http,
        login,
        mail_origin,
        mail_http,
        sessions: Mutex::new(SessionStore::new()),
        codes: Mutex::new(CodeStore::new()),
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
        .resolve("github.com", oidc)
        .resolve("api.github.com", oidc)
        // Regional KMS endpoints all resolve through the same proxy; the exact
        // host is set by the configured region at call time.
        .resolve("kms.us-east-1.amazonaws.com", local(KMS_HOST.local_port))
        .build()
        .context("could not build the enclave HTTP client")
}

/// Resolves every hostname to one loopback address. The mail client uses it to
/// send any `mta-sts.<domain>` and `dns.google` request to the OIDC forwarder,
/// whose parent-side relay dials the host named in the TLS ClientHello.
struct LoopbackResolver(std::net::SocketAddr);

impl reqwest::dns::Resolve for LoopbackResolver {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let address = self.0;
        Box::pin(async move { Ok(Box::new(std::iter::once(address)) as reqwest::dns::Addrs) })
    }
}

/// The client for MTA-STS policy fetches and DNS-over-HTTPS. Redirects are off
/// because RFC 8461 section 3.3 forbids following them. The resolver's non-zero
/// port is kept for URLs without an explicit port (hyper-util `set_port`).
fn build_mail_http_client() -> Result<Client> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let forwarder = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), OIDC_HOST.local_port);
    Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(LoopbackResolver(forwarder)))
        .build()
        .context("could not build the enclave mail HTTP client")
}

fn build_mail_origin(config: &MailConfig) -> Result<mail::Origin> {
    let sender: lettre::Address = config.sender.parse().context("invalid mail sender address")?;
    let dkim = mail::dkim_config(
        sender.domain(),
        &config.dkim_selector,
        &config.dkim_private_key_pem,
    )?;
    Ok(mail::Origin {
        from: config.from.parse().context("invalid mail from address")?,
        sender,
        helo: config.helo.clone(),
        dkim: Some(dkim),
    })
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

        EnclaveRequest::SendCode { email, app_id, app_name } => {
            send_code(enclave, &email, &app_id, &app_name).await?;
            Ok(EnclaveResponse::CodeSent)
        }

        EnclaveRequest::LoginKeys => Ok(EnclaveResponse::LoginKeys { jwks: enclave.login.jwks() }),

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

        EnclaveRequest::RunJob { session_id, job, auth_challenge_hash, github } => {
            validate_session_id(&session_id)?;
            // Claiming removes the session, so this job cannot be replayed.
            let channel = {
                let mut sessions = enclave.sessions.lock().await;
                sessions
                    .claim(&session_id, Instant::now())
                    .map_err(|_| anyhow!("unknown, expired, or already-used session"))
                    .context(failure::Failure::SessionUnknown)?
            };
            let (plaintext, response_key) = decrypt_job(&channel, &session_id, job)?;
            let job: WorkloadJob =
                serde_json::from_slice(&plaintext).context("invalid recovery job")?;
            let result = process_job(enclave, job, &auth_challenge_hash, github.as_ref()).await?;
            let (nonce, ciphertext) =
                response_key.seal(&serde_json::to_vec(&result)?, &session_id)?;
            let result = match result {
                WorkloadResult::EmailVerified { .. } => {
                    WorkloadResult::EmailVerified { id_token: String::new() }
                }
                WorkloadResult::GithubVerified { .. } => {
                    WorkloadResult::GithubVerified { id_token: String::new() }
                }
                other => other,
            };
            Ok(EnclaveResponse::JobCompleted {
                result,
                sealed_result: SealedResult {
                    nonce_b64: crypto::b64(nonce),
                    ciphertext_b64: crypto::b64(ciphertext),
                },
            })
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
) -> Result<(Zeroizing<Vec<u8>>, crypto::ResponseKey)> {
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
    github: Option<&GithubGrant>,
) -> Result<WorkloadResult> {
    match job {
        WorkloadJob::Enroll { credential, policy, stellar_dek_b64 } => {
            if credential.provider != policy.provider {
                return Err(anyhow!("credential provider does not match policy")
                    .context(failure::Failure::ProviderMismatch));
            }
            let claims =
                oidc::verify_id_token(
                    &enclave.http,
                    &enclave.login,
                    &credential,
                    &policy,
                    auth_challenge_hash,
                )
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
            let (record, signing_key) =
                open_record(enclave, &credential, &sealed_record_b64, auth_challenge_hash).await?;

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
                identity_commitment_hex: record.identity_commitment_hex,
                authorizations: signed,
                stellar_device_wrap_b64,
            })
        }

        WorkloadJob::Confirm { credential, sealed_record_b64, stellar_dek_b64 } => {
            let (record, signing_key) =
                open_record(enclave, &credential, &sealed_record_b64, auth_challenge_hash).await?;
            let (compressed, x, y) = crypto::recovery_public_parts(&signing_key);
            let dek_matches = match stellar_dek_b64 {
                None => None,
                Some(claimed) => {
                    let claimed = Zeroizing::new(crypto::unb64(&claimed)?);
                    let sealed = record
                        .stellar_dek_b64
                        .as_deref()
                        .map(crypto::unb64)
                        .transpose()?
                        .map(Zeroizing::new);
                    Some(sealed.is_some_and(|sealed| {
                        bool::from(sealed.as_slice().ct_eq(claimed.as_slice()))
                    }))
                }
            };
            Ok(WorkloadResult::Confirmed {
                identity_commitment_hex: record.identity_commitment_hex,
                policy_hash_hex: crypto::hex(&crypto::policy_hash(&record.policy)),
                recovery_pubkey_compressed_b64: crypto::b64(compressed),
                recovery_x_hex: crypto::hex(&x),
                recovery_y_hex: crypto::hex(&y),
                dek_matches,
            })
        }

        WorkloadJob::VerifyEmail { email, code, client_nonce } => {
            validate_client_nonce(&client_nonce)?;
            let email = login::normalize_email(&email);
            let app_id = enclave
                .codes
                .lock()
                .await
                .verify(&email, &code, Instant::now())
                .ok_or_else(|| anyhow!("code rejected").context(failure::Failure::CodeRejected))?;
            let id_token = enclave.login.issue(
                &email,
                &format!("{app_id}.{client_nonce}"),
                oidc::unix_time()?,
            )?;
            Ok(WorkloadResult::EmailVerified { id_token })
        }

        WorkloadJob::VerifyGithub { code_verifier, client_nonce } => {
            let grant = github.ok_or_else(|| anyhow!("github grant is missing"))?;
            validate_client_nonce(&client_nonce)?;
            validate_app_id(&grant.app_id)?;
            validate_code_verifier(&code_verifier)?;
            let user = github::user_for_code(&enclave.http, grant, &code_verifier).await?;
            let id_token = enclave.login.issue_github(
                &user,
                &grant.client_id,
                &format!("{}.{client_nonce}", grant.app_id),
                oidc::unix_time()?,
            )?;
            Ok(WorkloadResult::GithubVerified { id_token })
        }
    }
}

/// Mail a fresh code to `email`.
///
/// The code store is locked only to reserve the entry and to give it back; the
/// SMTP exchange runs without it. Errors from the mail path are replaced by a
/// fixed message because they can quote the recipient's address.
async fn send_code(enclave: &Enclave, email: &str, app_id: &str, app_name: &str) -> Result<()> {
    let origin = enclave.mail_origin.as_ref().ok_or_else(|| {
        anyhow!("this enclave has no mail identity").context(failure::Failure::EmailUnavailable)
    })?;
    let (normalized, address) = validate_send_code(email, app_id, app_name)
        .context(failure::Failure::EmailInvalid)?;

    let code = codes::generate_code();
    enclave
        .codes
        .lock()
        .await
        .reserve(&normalized, app_id, code.clone(), Instant::now())
        .map_err(|error| match error {
            CodeError::Cooldown => {
                anyhow!("a code was sent too recently").context(failure::Failure::CodeCooldown)
            }
            CodeError::AtCapacity => anyhow!("code store is at capacity"),
        })?;

    let content = mail::code_content(app_name, &code, &normalized);
    let dial = |host: String| async move {
        Ok(vec![outbound::open_smtp_tunnel(&host).await?])
    };
    let sent = mail::send_code(&enclave.mail_http, origin, &address, &content, dial).await;
    if sent.is_err() {
        enclave.codes.lock().await.release(&normalized);
    }
    sent.map(|_| ())
        .map_err(|_| anyhow!("mail delivery failed").context(failure::Failure::EmailUndeliverable))
}

fn validate_send_code(
    email: &str,
    app_id: &str,
    app_name: &str,
) -> Result<(String, lettre::Address)> {
    let normalized = login::normalize_email(email);
    if normalized.is_empty()
        || normalized.len() > 254
        || !normalized.bytes().all(|byte| byte.is_ascii_graphic())
    {
        bail!("email address is malformed");
    }
    let address: lettre::Address = normalized.parse().context("email address is malformed")?;
    if app_id.is_empty()
        || app_id.len() > 64
        || !app_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("app id is malformed");
    }
    if app_name.is_empty()
        || app_name.len() > 40
        || !app_name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'.' | b',' | b'\'' | b'&' | b'-')
        })
    {
        bail!("app name is malformed");
    }
    Ok((normalized, address))
}

fn validate_client_nonce(nonce: &str) -> Result<()> {
    if nonce.len() != 43
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        bail!("client nonce is malformed");
    }
    Ok(())
}

/// The app id is bound into the token's nonce, so it must be a canonical UUID.
fn validate_app_id(app_id: &str) -> Result<()> {
    let canonical = app_id.len() == 36
        && app_id.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    if !canonical {
        bail!("app id is not a canonical UUID");
    }
    Ok(())
}

/// A PKCE verifier is 43 to 128 unreserved characters (RFC 7636 section 4.1).
fn validate_code_verifier(verifier: &str) -> Result<()> {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        bail!("code verifier is malformed");
    }
    Ok(())
}

/// Unseal a record and prove the credential is the identity it was sealed for.
///
/// Everything a job may do with a record — sign with its key, release its DEK,
/// or only describe it — comes after this, so no path can skip the check.
async fn open_record(
    enclave: &Enclave,
    credential: &ProviderCredential,
    sealed_record_b64: &str,
    auth_challenge_hash: &str,
) -> Result<(SealedRecoveryRecord, SigningKey)> {
    let record_bytes = enclave.root.unseal(&crypto::unb64(sealed_record_b64)?)?;
    let record: SealedRecoveryRecord =
        serde_json::from_slice(&record_bytes).context("invalid sealed recovery record")?;
    if record.version != 1 || credential.provider != record.policy.provider {
        return Err(anyhow!("sealed recovery policy mismatch")
            .context(failure::Failure::ProviderMismatch));
    }

    let claims = oidc::verify_id_token(
        &enclave.http,
        &enclave.login,
        credential,
        &record.policy,
        auth_challenge_hash,
    )
    .await?;
    let identity = crypto::identity_commitment(&record.policy, &claims.sub);
    if crypto::hex(&identity) != record.identity_commitment_hex {
        bail!("social identity does not match enrolled identity");
    }

    let secret_bytes = Zeroizing::new(crypto::unb64(&record.recovery_private_key_b64)?);
    let secret =
        SecretKey::from_slice(&secret_bytes).context("invalid sealed recovery private key")?;
    Ok((record, SigningKey::from(secret)))
}

#[cfg(test)]
mod tests {
    use super::{
        validate_app_id, validate_client_nonce, validate_code_verifier, validate_send_code,
        validate_session_id,
    };

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

    #[test]
    fn send_code_inputs_are_validated_and_normalized() {
        let (email, address) =
            validate_send_code("  User@Gmail.COM ", "0f9d5a1c-3b2e", "Acme & Co., it's-ok").unwrap();
        assert_eq!(email, "user@gmail.com");
        assert_eq!(address.domain(), "gmail.com");

        assert!(validate_send_code("", "app", "Acme").is_err());
        assert!(validate_send_code("not-an-address", "app", "Acme").is_err());
        assert!(validate_send_code("a b@gmail.com", "app", "Acme").is_err());
        assert!(validate_send_code("a@gmail.com\r\nBcc: x@y.z", "app", "Acme").is_err());
        assert!(validate_send_code("usér@gmail.com", "app", "Acme").is_err());
        let long = format!("{}@gmail.com", "a".repeat(250));
        assert!(validate_send_code(&long, "app", "Acme").is_err());

        assert!(validate_send_code("a@gmail.com", "", "Acme").is_err());
        assert!(validate_send_code("a@gmail.com", &"a".repeat(65), "Acme").is_err());
        assert!(validate_send_code("a@gmail.com", "app_id", "Acme").is_err());
        assert!(validate_send_code("a@gmail.com", "app", "").is_err());
        assert!(validate_send_code("a@gmail.com", "app", &"a".repeat(41)).is_err());
        assert!(validate_send_code("a@gmail.com", "app", "Acme\nBcc: x").is_err());
        assert!(validate_send_code("a@gmail.com", "app", "<b>Acme</b>").is_err());
    }

    #[test]
    fn app_id_must_be_a_canonical_uuid() {
        assert!(validate_app_id("0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f").is_ok());
        assert!(validate_app_id("0F9D5A1C-3B2E-4C5A-8D7F-1A2B3C4D5E6F").is_ok());
        assert!(validate_app_id("").is_err());
        assert!(validate_app_id("0f9d5a1c3b2e4c5a8d7f1a2b3c4d5e6f").is_err());
        assert!(validate_app_id("0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6").is_err());
        assert!(validate_app_id("0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6g").is_err());
        assert!(validate_app_id("0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f.").is_err());
        assert!(validate_app_id("0f9d5a1c_3b2e-4c5a-8d7f-1a2b3c4d5e6f").is_err());
    }

    #[test]
    fn code_verifier_follows_rfc_7636() {
        assert!(validate_code_verifier(&"a".repeat(43)).is_ok());
        assert!(validate_code_verifier(&"a".repeat(128)).is_ok());
        assert!(validate_code_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").is_ok());
        assert!(validate_code_verifier(&format!("{}-._~", "a".repeat(40))).is_ok());
        assert!(validate_code_verifier(&"a".repeat(42)).is_err());
        assert!(validate_code_verifier(&"a".repeat(129)).is_err());
        assert!(validate_code_verifier(&format!("{}=", "a".repeat(43))).is_err());
        assert!(validate_code_verifier(&format!("{} ", "a".repeat(43))).is_err());
        assert!(validate_code_verifier(&format!("{}&x=1", "a".repeat(43))).is_err());
    }

    #[test]
    fn client_nonce_must_be_a_base64url_sha256() {
        assert!(validate_client_nonce("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").is_ok());
        assert!(validate_client_nonce("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c").is_err());
        assert!(validate_client_nonce("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cMM").is_err());
        assert!(validate_client_nonce("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw.cM").is_err());
        assert!(validate_client_nonce("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw=cM").is_err());
    }
}

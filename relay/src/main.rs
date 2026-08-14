//! The parent-side relay for the Cavos confidential recovery enclave.
//!
//! This process runs on the EC2 instance that hosts the enclave and does one
//! thing: move opaque frames between the control plane (over HTTP) and the
//! enclave (over vsock).
//!
//! # It is not trusted, and that is the point
//!
//! Everything of value is protected end to end *past* this process:
//!
//!   * the user's OIDC credential is encrypted in the browser to a P-256 key
//!     that only the enclave holds, so the relay forwards ciphertext;
//!   * the attestation document is signed by the AWS Nitro PKI, so the relay
//!     cannot forge one or swap in a key of its own;
//!   * the KMS key policy requires the enclave's PCR0 measurement, so the AWS
//!     credentials this instance holds cannot decrypt anything on their own.
//!
//! A compromised relay can therefore deny service, and that is the whole of its
//! power. It cannot read a credential, recover a wallet, or convince a browser
//! to talk to an enclave that is not the published image. Keeping it this
//! boring is deliberate: it means the security review lives in the enclave and
//! the SDK, not here.
//!
//! The shared secret below is an abuse control, not a security boundary. It
//! stops the open internet from queueing work onto the enclave; it is not what
//! keeps user data safe.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

/// vsock port the enclave listens on. Must match the enclave's `SERVICE_PORT`.
const ENCLAVE_PORT: u32 = 5005;

/// vsock port this process serves the enclave's configuration on.
///
/// `nitro-cli run-enclave` cannot pass environment variables, and baking a
/// rotating credential into the image would change its measurement, so the
/// enclave asks for its configuration here at startup instead.
const CONFIG_PORT: u32 = 5006;

/// vsock port the enclave reports startup failures on.
///
/// An enclave's console is invisible unless it was launched in debug mode, and
/// debug mode zeroes its PCRs — which means KMS refuses to release the root key
/// in exactly the configuration where the enclave could explain itself. Without
/// this channel a production enclave that will not start is undiagnosable.
const LOG_PORT: u32 = 5007;

/// Ceiling on a response frame from the enclave. Matches the enclave's own
/// inbound limit, so neither side can be made to allocate without bound.
const MAX_FRAME_BYTES: u32 = 256 * 1024;

/// How long to wait on the enclave before giving up. The enclave answers in
/// milliseconds; anything approaching this means it is wedged, and failing fast
/// is better than holding the control plane's request open.
const ENCLAVE_TIMEOUT: Duration = Duration::from_secs(15);

struct Relay {
    enclave_cid: u32,
    /// Presented by the control plane in `x-cavos-relay-key`. Abuse control.
    shared_secret: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let relay = Arc::new(Relay {
        enclave_cid: required("CAVOS_ENCLAVE_CID")?
            .parse()
            .context("CAVOS_ENCLAVE_CID must be a number")?,
        shared_secret: required("CAVOS_RELAY_SHARED_SECRET")?,
    });
    let bind: SocketAddr = std::env::var("CAVOS_RELAY_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()
        .context("CAVOS_RELAY_BIND must be host:port")?;

    let app = Router::new()
        // Liveness for the load balancer. Reaches into the enclave so a wedged
        // enclave takes the instance out of service rather than black-holing.
        .route("/health", get(health))
        // One route per enclave request. The relay does not interpret bodies
        // beyond checking they are JSON.
        .route("/sessions", post(open_session))
        .route("/jobs", post(run_job))
        .with_state(Arc::clone(&relay));

    // Serve the enclave's configuration before it starts. Only the enclave can
    // reach this: vsock is not routable from anywhere else.
    tokio::spawn(async move {
        if let Err(error) = serve_config().await {
            tracing::error!(%error, "configuration service stopped");
        }
    });

    tokio::spawn(async move {
        if let Err(error) = serve_enclave_log().await {
            tracing::error!(%error, "enclave log service stopped");
        }
    });

    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, cid = relay.enclave_cid, "relay listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

/// Surface the enclave's startup failures in the parent's journal.
///
/// The message is written by the measured enclave code, so it is as trustworthy
/// as the enclave is — but it is logged as data, never acted on.
async fn serve_enclave_log() -> Result<()> {
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, LOG_PORT))
        .context("could not bind the enclave log port")?;
    tracing::info!(port = LOG_PORT, "enclave log service listening");

    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut header = [0u8; 4];
            if stream.read_exact(&mut header).await.is_err() {
                return;
            }
            let length = u32::from_be_bytes(header);
            if length == 0 || length > 8192 {
                return;
            }
            let mut body = vec![0u8; length as usize];
            if stream.read_exact(&mut body).await.is_err() {
                return;
            }
            tracing::error!(message = %String::from_utf8_lossy(&body), "enclave reported a startup failure");
        });
    }
}

/// Answer the enclave's configuration request, once per connection.
///
/// The values are read fresh each time rather than cached, so restarting the
/// enclave picks up rotated instance credentials without restarting the relay.
async fn serve_config() -> Result<()> {
    let region = required("AWS_REGION")?;
    let root_key_param = required("CAVOS_ROOT_KEY_PARAM")?;

    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, CONFIG_PORT))
        .context("could not bind the configuration port")?;
    tracing::info!(port = CONFIG_PORT, "configuration service listening");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let region = region.clone();
        let root_key_param = root_key_param.clone();

        tokio::spawn(async move {
            let result = async {
                // The request body is ignored; connecting is the request.
                let mut header = [0u8; 4];
                stream.read_exact(&mut header).await?;
                let length = u32::from_be_bytes(header);
                if length > 64 {
                    bail!("configuration request is implausibly large");
                }
                let mut discard = vec![0u8; length as usize];
                stream.read_exact(&mut discard).await?;

                let config = load_config(&region, &root_key_param).await?;
                let body = serde_json::to_vec(&config)?;
                let length = u32::try_from(body.len())?;
                stream.write_all(&length.to_be_bytes()).await?;
                stream.write_all(&body).await?;
                stream.flush().await?;
                Ok::<_, anyhow::Error>(())
            }
            .await;

            if let Err(error) = result {
                tracing::error!(%error, "could not serve configuration");
            }
        });
    }
}

#[derive(serde::Serialize)]
struct EnclaveConfig {
    region: String,
    wrapped_root_key_b64: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

/// Gather what the enclave needs: the wrapped root key from Parameter Store,
/// and this instance's role credentials from IMDS.
///
/// Handing over credentials is safe because they are not authority on their
/// own. The KMS key policy releases the root key only against an attestation
/// measuring to the published enclave image, which this process cannot produce.
async fn load_config(region: &str, root_key_param: &str) -> Result<EnclaveConfig> {
    let wrapped = ssm_parameter(region, root_key_param).await?;
    let creds = imds_credentials().await?;
    Ok(EnclaveConfig {
        region: region.to_string(),
        wrapped_root_key_b64: wrapped,
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: Some(creds.token),
    })
}

async fn ssm_parameter(region: &str, name: &str) -> Result<String> {
    // Shelling out to the AWS CLI keeps SigV4 and credential resolution out of
    // this binary. The relay is untrusted, so there is nothing to gain by
    // hardening it; simplicity is worth more here.
    let output = tokio::process::Command::new("aws")
        .args(["ssm", "get-parameter", "--name", name, "--region", region,
               "--query", "Parameter.Value", "--output", "text"])
        .output()
        .await
        .context("could not run the AWS CLI")?;
    if !output.status.success() {
        bail!("ssm get-parameter failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

struct Credentials {
    access_key_id: String,
    secret_access_key: String,
    token: String,
}

async fn imds_credentials() -> Result<Credentials> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let token = client
        .put("http://169.254.169.254/latest/api/token")
        .header("x-aws-ec2-metadata-token-ttl-seconds", "300")
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let role = client
        .get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        .header("x-aws-ec2-metadata-token", &token)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let creds: serde_json::Value = client
        .get(format!(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/{}",
            role.trim()
        ))
        .header("x-aws-ec2-metadata-token", &token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let field = |key: &str| -> Result<String> {
        creds
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("IMDS credentials are missing {key}"))
    };
    Ok(Credentials {
        access_key_id: field("AccessKeyId")?,
        secret_access_key: field("SecretAccessKey")?,
        token: field("Token")?,
    })
}

async fn health(State(relay): State<Arc<Relay>>) -> Response {
    match relay.call(&serde_json::json!({ "request": "ping" })).await {
        Ok(_) => (StatusCode::OK, "ok").into_response(),
        Err(error) => {
            tracing::error!(%error, "enclave health check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "enclave unavailable").into_response()
        }
    }
}

async fn open_session(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    forward(relay, headers, "open_session", body).await
}

async fn run_job(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    forward(relay, headers, "run_job", body).await
}

/// Tag the caller's body with the request kind and hand it to the enclave.
///
/// The relay sets `request` itself rather than trusting the body, so a caller
/// cannot reach a different enclave operation than the route it posted to.
async fn forward(
    relay: Arc<Relay>,
    headers: HeaderMap,
    request: &str,
    mut body: Value,
) -> Response {
    if !authorized(&relay, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let Some(object) = body.as_object_mut() else {
        return (StatusCode::BAD_REQUEST, "body must be a JSON object").into_response();
    };
    object.insert("request".into(), Value::String(request.into()));

    match relay.call(&body).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => {
            // The enclave's own errors are already coarse by design; anything
            // here is a transport failure, which is ours to log and theirs to
            // retry.
            tracing::error!(%error, request, "enclave call failed");
            (StatusCode::BAD_GATEWAY, "enclave call failed").into_response()
        }
    }
}

/// Constant-time comparison of the shared secret.
///
/// Length is compared first only to avoid indexing past the end; the byte loop
/// itself does not short-circuit, so a timing signal cannot walk the secret out
/// one character at a time.
fn authorized(relay: &Relay, headers: &HeaderMap) -> bool {
    let Some(presented) = headers
        .get("x-cavos-relay-key")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let expected = relay.shared_secret.as_bytes();
    let presented = presented.as_bytes();
    if presented.len() != expected.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(presented) {
        difference |= a ^ b;
    }
    difference == 0
}

impl Relay {
    /// One request, one vsock connection. Connections are cheap and this avoids
    /// having to reason about a pooled stream left half-written by a timeout.
    async fn call(&self, request: &Value) -> Result<Value> {
        tokio::time::timeout(ENCLAVE_TIMEOUT, self.exchange(request))
            .await
            .map_err(|_| anyhow::anyhow!("enclave did not answer within {ENCLAVE_TIMEOUT:?}"))?
    }

    async fn exchange(&self, request: &Value) -> Result<Value> {
        let mut stream = VsockStream::connect(VsockAddr::new(self.enclave_cid, ENCLAVE_PORT))
            .await
            .context("could not connect to the enclave")?;

        let body = serde_json::to_vec(request)?;
        let length = u32::try_from(body.len()).context("request is too large")?;
        if length > MAX_FRAME_BYTES {
            bail!("request of {length} bytes exceeds the frame limit");
        }
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&body).await?;
        stream.flush().await?;

        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.context("short response header")?;
        let length = u32::from_be_bytes(header);
        if length == 0 || length > MAX_FRAME_BYTES {
            bail!("response length {length} is out of range");
        }
        let mut response = vec![0u8; length as usize];
        stream.read_exact(&mut response).await.context("short response body")?;

        serde_json::from_slice(&response).context("enclave returned malformed JSON")
    }
}

fn required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("required environment variable {name} is missing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay() -> Relay {
        Relay { enclave_cid: 16, shared_secret: "correct-horse".into() }
    }

    fn headers_with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-cavos-relay-key", value.parse().unwrap());
        headers
    }

    #[test]
    fn accepts_the_configured_secret() {
        assert!(authorized(&relay(), &headers_with("correct-horse")));
    }

    #[test]
    fn rejects_a_wrong_or_missing_secret() {
        assert!(!authorized(&relay(), &headers_with("wrong-horse")));
        assert!(!authorized(&relay(), &headers_with("correct-hors")));
        assert!(!authorized(&relay(), &headers_with("correct-horsee")));
        assert!(!authorized(&relay(), &HeaderMap::new()));
    }
}

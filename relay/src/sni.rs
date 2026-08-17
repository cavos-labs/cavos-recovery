//! Outbound TLS for the enclave, routed by the name it asks for.
//!
//! # Why this exists
//!
//! `vsock-proxy` takes its destination on the command line, so one instance
//! serves exactly one host. The enclave, however, resolves every provider it
//! may verify a token against — `accounts.google.com`, `www.googleapis.com`,
//! `appleid.apple.com`, `securetoken.google.com` — to a single local port. One
//! fixed-destination proxy behind that port therefore sends all four to
//! whichever host it was started with.
//!
//! That was `www.googleapis.com`, which happens to be where both Google's and
//! Firebase's JWKS live, so those two worked and looked like the design working.
//! Apple's keys are at `appleid.apple.com`, so every Apple verification opened a
//! TLS session to Google's servers, failed the certificate check inside the
//! enclave, and surfaced as an opaque `request_failed`.
//!
//! This reads the name out of the ClientHello and dials that instead.
//!
//! # Why routing on an untrusted parent is safe
//!
//! Nothing here is trusted, and nothing here needs to be. The enclave completes
//! the TLS handshake itself and validates the certificate against the real
//! hostname, so a parent that routes a connection to the wrong host produces a
//! failed handshake, not a redirected one. It cannot read the traffic: it is
//! ciphertext negotiated end to end past this process.
//!
//! The allowlist below is therefore not a security boundary either — the
//! enclave's own `oidc.rs` decides which issuer/JWKS pairs it will accept. It is
//! here so that a bug cannot turn the parent into an open relay to arbitrary
//! hosts on the internet.
//!
//! # Why not fix this in the enclave
//!
//! Giving each provider its own port would work and would be a smaller diff. It
//! would also change the enclave image, and so PCR0 — which means a new
//! measurement pinned in `@cavos/kit`, a KMS key policy update, and an ordered
//! rollout across every app holding the old pin. The parent is not measured.
//! Fixing it here costs one binary on a host that is already untrusted.


use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

/// Hosts the enclave is allowed to reach through here.
///
/// Every entry is a provider JWKS or discovery host. Adding a provider means
/// adding it here — and, unlike the port-per-provider alternative, nothing in
/// the measured image changes.
const ALLOWED_HOSTS: &[&str] = &[
    "accounts.google.com",
    "www.googleapis.com",
    "appleid.apple.com",
    "securetoken.google.com",
];

/// A ClientHello is small. This is far above any real one and well below
/// anything that would let a peer make us buffer meaningfully.
const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// Serve the enclave's outbound TLS on `vsock_port`, dialing whatever host each
/// connection names.
pub async fn serve(vsock_port: u32) -> Result<()> {
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port))
        .with_context(|| format!("could not bind vsock port {vsock_port}"))?;
    tracing::info!(port = vsock_port, "outbound TLS forwarder listening");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "outbound accept failed");
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(error) = forward(stream).await {
                // The enclave sees a closed connection and reports its own
                // failure; this is the only place the reason is written down.
                tracing::warn!(%error, "outbound forward failed");
            }
        });
    }
}

async fn forward(mut enclave: tokio_vsock::VsockStream) -> Result<()> {
    // Buffer the ClientHello, since the destination cannot be chosen until the
    // name inside it is known, and it still has to reach the server afterwards.
    let mut hello = Vec::with_capacity(1024);
    let host = loop {
        let mut chunk = [0u8; 2048];
        let read = enclave.read(&mut chunk).await.context("reading ClientHello")?;
        if read == 0 {
            bail!("connection closed before the ClientHello was complete");
        }
        hello.extend_from_slice(&chunk[..read]);
        match server_name(&hello) {
            Ok(Some(name)) => break name,
            // Not enough bytes yet.
            Ok(None) if hello.len() < MAX_CLIENT_HELLO => continue,
            Ok(None) => bail!("no server name after {} bytes", hello.len()),
            Err(error) => return Err(error),
        }
    };

    if !ALLOWED_HOSTS.contains(&host.as_str()) {
        bail!("host {host} is not an allowed outbound destination");
    }

    let mut upstream = TcpStream::connect((host.as_str(), 443))
        .await
        .with_context(|| format!("connecting to {host}:443"))?;
    upstream.set_nodelay(true).ok();
    upstream
        .write_all(&hello)
        .await
        .with_context(|| format!("forwarding the ClientHello to {host}"))?;

    tracing::debug!(%host, "outbound TLS session opened");
    tokio::io::copy_bidirectional(&mut enclave, &mut upstream)
        .await
        .with_context(|| format!("relaying to {host}"))?;
    Ok(())
}

/// The SNI host from a TLS ClientHello.
///
/// `Ok(None)` means the buffer is a well-formed prefix that does not yet
/// contain the name — read more and call again. Every field is bounds-checked
/// against the slice, so a truncated or hostile record cannot panic here.
fn server_name(buffer: &[u8]) -> Result<Option<String>> {
    let mut reader = Reader::new(buffer);

    // Record header: a handshake record carrying a ClientHello.
    if reader.u8()? != 0x16 {
        bail!("not a TLS handshake record");
    }
    reader.skip(2)?; // legacy record version
    let record_len = reader.u16()? as usize;
    let Some(mut body) = reader.slice(record_len) else {
        return Ok(None);
    };

    if body.u8()? != 0x01 {
        bail!("not a ClientHello");
    }
    body.skip(3)?; // handshake length
    body.skip(2)?; // client version
    body.skip(32)?; // random

    let session_id = body.u8()? as usize;
    body.skip(session_id)?;

    let cipher_suites = body.u16()? as usize;
    body.skip(cipher_suites)?;

    let compression = body.u8()? as usize;
    body.skip(compression)?;

    let extensions_len = body.u16()? as usize;
    let Some(mut extensions) = body.slice(extensions_len) else {
        return Ok(None);
    };

    while extensions.remaining() >= 4 {
        let kind = extensions.u16()?;
        let len = extensions.u16()? as usize;
        let Some(mut extension) = extensions.slice(len) else {
            return Ok(None);
        };
        if kind != 0x0000 {
            continue;
        }
        // server_name_list: length, then entries of type + length + name.
        extension.skip(2)?;
        while extension.remaining() >= 3 {
            let name_type = extension.u8()?;
            let name_len = extension.u16()? as usize;
            let Some(name) = extension.slice(name_len) else {
                return Ok(None);
            };
            // Type 0 is host_name; nothing else has ever been defined.
            if name_type == 0 {
                let host = std::str::from_utf8(name.rest())
                    .context("server name is not valid UTF-8")?;
                return Ok(Some(host.to_ascii_lowercase()));
            }
        }
    }

    // A ClientHello with no SNI is legal TLS and useless to us: there is no way
    // to know where it should go.
    bail!("ClientHello carries no server name")
}

/// Bounds-checked cursor. Every accessor either stays inside the slice or
/// fails; nothing here indexes directly.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }

    fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at.min(self.bytes.len())..]
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(count)
            .ok_or_else(|| anyhow!("length overflow"))?;
        if end > self.bytes.len() {
            bail!("truncated");
        }
        let taken = &self.bytes[self.at..end];
        self.at = end;
        Ok(taken)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn skip(&mut self, count: usize) -> Result<()> {
        self.take(count).map(|_| ())
    }

    /// A sub-reader over the next `count` bytes, or `None` when the buffer does
    /// not hold them yet. Distinct from `take`, which treats short input as an
    /// error: here it means "read more from the socket".
    fn slice(&mut self, count: usize) -> Option<Reader<'a>> {
        let end = self.at.checked_add(count)?;
        if end > self.bytes.len() {
            return None;
        }
        let sub = Reader::new(&self.bytes[self.at..end]);
        self.at = end;
        Some(sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a ClientHello carrying `host`, with the field widths a real one
    /// has, so the parser is exercised on the shape it will actually meet.
    fn client_hello(host: &str) -> Vec<u8> {
        let mut sni = vec![0x00];
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());

        let mut list = ((sni.len()) as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&sni);

        let mut extension = vec![0x00, 0x00];
        extension.extend_from_slice(&(list.len() as u16).to_be_bytes());
        extension.extend_from_slice(&list);

        let mut body = vec![0x01, 0x00, 0x00, 0x00];
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0x00); // no session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // one compression method
        body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        body.extend_from_slice(&extension);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn reads_the_name_the_enclave_asks_for() {
        for host in ALLOWED_HOSTS {
            let hello = client_hello(host);
            assert_eq!(server_name(&hello).unwrap().as_deref(), Some(*host));
        }
    }

    #[test]
    fn lowercases_the_name() {
        // SNI is case-insensitive, and the allowlist is compared literally.
        let hello = client_hello("AppleID.Apple.COM");
        assert_eq!(
            server_name(&hello).unwrap().as_deref(),
            Some("appleid.apple.com")
        );
    }

    #[test]
    fn asks_for_more_bytes_rather_than_guessing() {
        // The parser sees a prefix on nearly every real connection, because a
        // ClientHello does not arrive in one read. Treating that as an error
        // would fail every handshake.
        let hello = client_hello("appleid.apple.com");
        for cut in 5..hello.len() {
            assert_eq!(
                server_name(&hello[..cut]).unwrap(),
                None,
                "a {cut}-byte prefix should ask for more, not resolve"
            );
        }
        assert!(server_name(&hello).unwrap().is_some());
    }

    #[test]
    fn refuses_what_is_not_a_client_hello() {
        assert!(server_name(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]).is_err());
        let mut not_hello = client_hello("appleid.apple.com");
        not_hello[5] = 0x02; // ServerHello
        assert!(server_name(&not_hello).is_err());
    }

    #[test]
    fn does_not_panic_on_hostile_lengths() {
        let hello = client_hello("appleid.apple.com");
        // Every single-byte corruption either parses, asks for more, or errors.
        // None of them may panic — this runs on input from inside the enclave,
        // but the parser is the kind of code that gets reused somewhere hostile.
        for index in 0..hello.len() {
            for value in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut corrupted = hello.clone();
                corrupted[index] = value;
                let _ = server_name(&corrupted);
            }
        }
    }
}

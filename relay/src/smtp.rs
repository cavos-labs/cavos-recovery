//! Outbound SMTP for the enclave, to the mail exchanger it names.
//!
//! The enclave sends one frame holding an MX hostname and then speaks SMTP over
//! the same stream. STARTTLS is negotiated inside the enclave against the real
//! hostname, so this process only moves bytes it cannot read or alter without
//! failing the handshake. Like `sni`, the checks here keep a bug from turning
//! the parent into an open relay; they are not the security boundary.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

const SMTP_PORT: u16 = 25;
const MAX_HOST_FRAME: usize = 255;
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve the enclave's SMTP requests on `vsock_port`.
pub async fn serve(vsock_port: u32) -> Result<()> {
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port))
        .with_context(|| format!("could not bind vsock port {vsock_port}"))?;
    tracing::info!(port = vsock_port, "outbound SMTP forwarder listening");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "SMTP accept failed");
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(error) = forward(stream).await {
                tracing::warn!(%error, "SMTP forward failed");
            }
        });
    }
}

async fn forward(mut enclave: VsockStream) -> Result<()> {
    let host = tokio::time::timeout(FRAME_TIMEOUT, read_host(&mut enclave))
        .await
        .context("timed out waiting for the MX hostname")??;
    let mut upstream = tokio::time::timeout(CONNECT_TIMEOUT, connect(&host))
        .await
        .context("timed out connecting to the MX")??;
    upstream.set_nodelay(true).ok();
    tokio::io::copy_bidirectional(&mut enclave, &mut upstream)
        .await
        .context("relaying SMTP")?;
    Ok(())
}

async fn read_host<S>(stream: &mut S) -> Result<String>
where
    S: AsyncReadExt + Unpin,
{
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.context("short frame header")?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_HOST_FRAME {
        bail!("hostname frame length {length} is out of range");
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.context("short frame body")?;
    let host = String::from_utf8(body).context("hostname is not UTF-8")?;
    if !valid_hostname(&host) {
        bail!("not an acceptable MX hostname");
    }
    Ok(host)
}

/// A DNS name made of `[a-z0-9.-]`, with at least one dot, no empty or
/// oversized label, and a final label that is not numeric. The last rule keeps
/// IP literals in every spelling `getaddrinfo` accepts (`1.2.3.4`, `0x7f.1`)
/// out of the resolver.
fn valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.contains('.') {
        return false;
    }
    if !host
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-')
    {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    let mut labels = host.split('.');
    if labels.clone().any(|label| label.is_empty() || label.len() > 63) {
        return false;
    }
    labels.next_back().is_some_and(|last| last.bytes().any(|byte| byte.is_ascii_lowercase()))
}

fn is_public(address: &Ipv4Addr) -> bool {
    !(address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_multicast())
}

async fn connect(host: &str) -> Result<TcpStream> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, SMTP_PORT))
        .await
        .context("resolving the MX")?
        .filter(|address| matches!(address, SocketAddr::V4(v4) if is_public(v4.ip())))
        .collect();
    if addresses.is_empty() {
        bail!("the MX has no public IPv4 address");
    }
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.map_or_else(
        || anyhow::anyhow!("no address to connect to"),
        |error| anyhow::Error::new(error).context("connecting to the MX"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_mx_hostnames() {
        for host in [
            "gmail-smtp-in.l.google.com",
            "alt1.gmail-smtp-in.l.google.com",
            "outlook-com.olc.protection.outlook.com",
            "mx1.example.co.uk",
            "mail-1.example.xn--p1ai",
        ] {
            assert!(valid_hostname(host), "{host}");
        }
    }

    #[test]
    fn refuses_anything_else() {
        for host in [
            "",
            "localhost",
            "1.2.3.4",
            "127.0.0.1",
            "0x7f.0.0.1",
            "0x7f.1",
            "example.123",
            "Example.com",
            "exa mple.com",
            "example.com\n",
            "example.com:25",
            "[::1]",
            "::1",
            "a..example.com",
            ".example.com",
            "example.com.",
            "ex_ample.com",
            "exämple.com",
        ] {
            assert!(!valid_hostname(host), "{host:?}");
        }
        assert!(!valid_hostname(&format!("{}.com", "a".repeat(64))));
        assert!(!valid_hostname(&format!("{}.com", "a.".repeat(130))));
    }

    #[test]
    fn only_public_addresses_are_dialed() {
        assert!(is_public(&Ipv4Addr::new(142, 250, 27, 26)));
        for address in [
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
        ] {
            assert!(!is_public(&address), "{address}");
        }
    }

    #[tokio::test]
    async fn reads_one_bounded_hostname_frame() {
        let mut good: &[u8] = b"\x00\x00\x00\x0emx.example.com\x00ignored";
        assert_eq!(read_host(&mut good).await.unwrap(), "mx.example.com");
        let mut empty: &[u8] = b"\x00\x00\x00\x00";
        assert!(read_host(&mut empty).await.is_err());
        let mut oversized: &[u8] = b"\x00\x00\x01\x00aaaa";
        assert!(read_host(&mut oversized).await.is_err());
        let mut bad_name: &[u8] = b"\x00\x00\x00\x09127.0.0.1";
        assert!(read_host(&mut bad_name).await.is_err());
        let mut truncated: &[u8] = b"\x00\x00\x00\x0fmx.exam";
        assert!(read_host(&mut truncated).await.is_err());
    }
}

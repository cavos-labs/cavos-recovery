//! Outbound HTTPS from inside the enclave.
//!
//! A Nitro enclave has no network device: its only channel to the world is
//! vsock to its parent instance. But the enclave still has to reach two kinds of
//! host — the provider's JWKS endpoint, to verify an ID token's signature, and
//! KMS, to unwrap the root sealing key.
//!
//! The shape is a forwarder: a listener on loopback inside the enclave accepts a
//! plain TCP connection and splices it to a vsock connection to the parent,
//! where `vsock-proxy` opens a TCP connection to the real host. Crucially, TLS
//! is negotiated **inside the enclave**, end to end with the real host, so the
//! parent relays ciphertext it cannot read or alter. `reqwest`'s `resolve()`
//! override points a hostname at the local port while leaving SNI, the `Host`
//! header, and certificate validation pointed at the real name.
//!
//! The parent is untrusted, and this design keeps it that way: the worst it can
//! do is refuse to forward, or forward somewhere else — and somewhere else
//! cannot produce a valid certificate for `accounts.google.com`, so the TLS
//! handshake inside the enclave fails and the token is never verified.
//!
//! Loopback is brought up explicitly rather than assumed. Enclave init images
//! differ, and a silently-down `lo` would surface as a confusing connection
//! refused much later.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_vsock::{VsockAddr, VsockStream};

/// The parent instance is always CID 3 from inside an enclave.
pub const PARENT_CID: u32 = 3;

/// One host the enclave is allowed to reach, and the parent vsock port whose
/// `vsock-proxy` is configured to open connections to it.
///
/// The mapping is fixed at build time and measured into PCR0. A parent that
/// wants the enclave to talk to a different host has to change the enclave
/// image, which changes the measurement, which the browser rejects.
#[derive(Debug, Clone, Copy)]
pub struct ProxiedHost {
    pub hostname: &'static str,
    pub vsock_port: u32,
    pub local_port: u16,
}

/// Bring up the loopback interface.
///
/// Equivalent to `ip link set lo up`, done with an ioctl because the runtime
/// image is distroless and has no shell or `ip` binary.
#[cfg(target_os = "linux")]
pub fn bring_up_loopback() -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};

    // struct ifreq is 40 bytes on Linux: 16 bytes of name, then a union.
    const IFNAMSIZ: usize = 16;
    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        bail!("could not open a socket to configure loopback");
    }
    // Wrap the descriptor so it is closed even if an error path returns early.
    let socket = unsafe { std::os::fd::OwnedFd::from_raw_fd(socket) };

    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (index, byte) in b"lo".iter().enumerate() {
        request.ifr_name[index] = *byte as libc::c_char;
    }
    debug_assert!(b"lo".len() < IFNAMSIZ);

    let read = unsafe { libc::ioctl(socket.as_raw_fd(), SIOCGIFFLAGS, &mut request) };
    if read < 0 {
        bail!("could not read loopback flags: {}", std::io::Error::last_os_error());
    }
    unsafe {
        request.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    }
    let written = unsafe { libc::ioctl(socket.as_raw_fd(), SIOCSIFFLAGS, &request) };
    if written < 0 {
        bail!("could not bring up loopback: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn bring_up_loopback() -> Result<()> {
    bail!("the enclave workload only runs on Linux")
}

/// Start a loopback listener that splices every connection to `host`'s vsock
/// port on the parent. Returns once the listener is bound, so callers can build
/// an HTTP client immediately without racing the first request.
pub async fn start_forwarder(host: ProxiedHost) -> Result<()> {
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, host.local_port));
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("could not bind the forwarder for {}", host.hostname))?;

    tokio::spawn(async move {
        loop {
            let (inbound, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    eprintln!("[outbound] accept failed for {}: {error}", host.hostname);
                    continue;
                }
            };
            tokio::spawn(async move {
                if let Err(error) = splice(inbound, host.vsock_port).await {
                    // Connection-level failures are routine (timeouts, resets)
                    // and carry no secret, so they are safe to log.
                    eprintln!("[outbound] relay to {} ended: {error}", host.hostname);
                }
            });
        }
    });
    Ok(())
}

async fn splice(mut inbound: TcpStream, vsock_port: u32) -> Result<()> {
    let mut outbound = VsockStream::connect(VsockAddr::new(PARENT_CID, vsock_port))
        .await
        .context("parent vsock proxy unavailable")?;
    // Copy in both directions until either side closes. `copy_bidirectional`
    // handles the half-close semantics TLS needs, and shuts both sides down on
    // completion, so no explicit shutdown is needed here.
    tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .context("relay failed")?;
    Ok(())
}

/// Read a length-prefixed frame from a vsock stream.
///
/// The parent is untrusted, so the declared length is checked against a ceiling
/// before anything is allocated: an attacker-chosen `u32` must not be able to
/// ask the enclave to reserve four gigabytes.
pub async fn read_frame<S>(stream: &mut S, max_len: u32) -> Result<Vec<u8>>
where
    S: AsyncReadExt + Unpin,
{
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.context("short frame header")?;
    let length = u32::from_be_bytes(header);
    if length == 0 || length > max_len {
        bail!("frame length {length} is out of range");
    }
    let mut body = vec![0u8; length as usize];
    stream.read_exact(&mut body).await.context("short frame body")?;
    Ok(body)
}

/// Write a length-prefixed frame.
pub async fn write_frame<S>(stream: &mut S, body: &[u8]) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let length = u32::try_from(body.len()).context("frame is too large to send")?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

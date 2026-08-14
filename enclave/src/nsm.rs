//! Attestation via the Nitro Security Module.
//!
//! Replaces the Confidential Space launcher socket. The NSM is a virtual device
//! the Nitro hypervisor exposes to the enclave and to nothing else; a document
//! it produces is signed by the AWS Nitro Attestation PKI and states the
//! enclave's measurements (PCRs). There is deliberately no development fallback
//! that fabricates a document — code that runs outside a real enclave must fail,
//! not quietly produce something unattested.
//!
//! Two kinds of document are requested, and they are not interchangeable:
//!
//!   * a *session* document, whose `public_key` is the P-256 channel key the
//!     browser will encrypt to, and whose `user_data` binds it to one session;
//!   * a *KMS* document, whose `public_key` is a single-use RSA key that KMS
//!     encrypts the unwrapped root key to.
//!
//! They must stay distinct because the document has only one `public_key` slot.
//! Reusing the session document for KMS would hand KMS a key the browser also
//! knows about, and reusing the KMS document for a session would publish an RSA
//! key the channel cannot use.

use anyhow::{anyhow, bail, Result};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use serde_bytes::ByteBuf;

use crate::crypto::sha256;

/// An open handle to the NSM device.
///
/// The driver is initialised once and shared: opening it per request would add
/// a syscall to every attestation for no benefit.
pub struct Nsm {
    fd: i32,
}

impl Nsm {
    pub fn open() -> Result<Self> {
        let fd = nsm_init();
        if fd < 0 {
            bail!("nitro security module unavailable (is this running inside an enclave?)");
        }
        Ok(Self { fd })
    }

    /// Attest to a session's channel key.
    ///
    /// `user_data` is `sha256(session_id)`, which stops the untrusted parent
    /// from replaying a document minted for one session as the answer to
    /// another. The channel key travels in `public_key` so the browser can take
    /// it from inside the signed document rather than trusting the JSON that
    /// carried it.
    pub fn attest_session(&self, channel_public_key: &[u8], session_id: &str) -> Result<Vec<u8>> {
        self.attest(
            Some(channel_public_key.to_vec()),
            Some(sha256(session_id.as_bytes()).to_vec()),
            None,
        )
    }

    /// Attest to a single-use RSA key so KMS can envelope a response to it.
    ///
    /// KMS checks this document against the key policy's
    /// `kms:RecipientAttestation:PCR0` condition, so a caller holding the same
    /// IAM credentials but running outside the enclave cannot decrypt.
    pub fn attest_for_kms(&self, rsa_public_key_der: &[u8]) -> Result<Vec<u8>> {
        self.attest(Some(rsa_public_key_der.to_vec()), None, None)
    }

    fn attest(
        &self,
        public_key: Option<Vec<u8>>,
        user_data: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let request = Request::Attestation {
            public_key: public_key.map(ByteBuf::from),
            user_data: user_data.map(ByteBuf::from),
            nonce: nonce.map(ByteBuf::from),
        };
        match nsm_process_request(self.fd, request) {
            Response::Attestation { document } => Ok(document),
            Response::Error(error) => Err(anyhow!("nsm attestation failed: {error:?}")),
            other => Err(anyhow!("nsm returned an unexpected response: {other:?}")),
        }
    }
}

impl Drop for Nsm {
    fn drop(&mut self) {
        nsm_exit(self.fd);
    }
}

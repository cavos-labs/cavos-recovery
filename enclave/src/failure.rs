//! Coarse failure classes, for requests the enclave refuses.
//!
//! # Why the enclave used to say nothing
//!
//! Every rejected request answered `request_failed`, with the real reason
//! printed to a stderr that production cannot read — an enclave's console needs
//! debug mode, and debug mode zeroes the PCRs, so the one configuration in which
//! it can explain itself is the one in which KMS will not talk to it.
//!
//! That is the right instinct pushed one step too far. Nothing must reveal
//! *what* a credential contained, or whether a particular identity owns a
//! particular wallet. But "the audience did not match" or "the JWKS host was
//! unreachable" reveals neither, and refusing to say which of fourteen checks
//! failed turned a one-line configuration bug into a day of bisecting through
//! production deploys.
//!
//! # What each class may and may not say
//!
//! A class names the *check* that failed, never the value that failed it. The
//! caller already holds the token, so telling them its audience was rejected
//! tells them nothing they could not read themselves; telling them a subject
//! did or did not match a sealed record would tell them something new, so no
//! class does that — an identity mismatch stays `request_failed`.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The policy the parent supplied is not one the enclave will verify
    /// against: an issuer/JWKS pair outside the allowlist, or missing fields.
    PolicyRejected,
    /// The credential and the policy name different providers. The first thing
    /// checked on any job, and the one that hid an Apple/Google mix-up behind
    /// an opaque failure for as long as Apple support has existed.
    ProviderMismatch,
    /// The token does not hash to the fingerprint beside it, or that
    /// fingerprint is not the one this session was opened for.
    CredentialBinding,
    /// The provider's key endpoint could not be reached or did not answer with
    /// a usable key set. Purely about the enclave's egress.
    JwksUnreachable,
    /// The token's signature, algorithm, or key id did not check out.
    SignatureRejected,
    /// The signature is good but a claim is not: issuer, audience, expiry, or
    /// an unverified email identity.
    ClaimsRejected,
    /// The authentication behind the token is too old, dated in the future, or
    /// missing the nonce the provider was asked to bind.
    AuthStale,
    /// No such session, or one already used. Sessions are single-use.
    SessionUnknown,
}

impl Failure {
    /// The wire code. Stable: the control plane and the SDK match on these, so
    /// renaming one is a breaking change even though it looks like a string.
    pub fn code(self) -> &'static str {
        match self {
            Failure::PolicyRejected => "policy_rejected",
            Failure::ProviderMismatch => "provider_mismatch",
            Failure::CredentialBinding => "credential_binding",
            Failure::JwksUnreachable => "jwks_unreachable",
            Failure::SignatureRejected => "signature_rejected",
            Failure::ClaimsRejected => "claims_rejected",
            Failure::AuthStale => "auth_stale",
            Failure::SessionUnknown => "session_unknown",
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// The class attached to `error`, or `request_failed` when none is.
///
/// Unclassified is the safe default in both directions: a check nobody has
/// thought about disclosing stays silent, and adding a class later is additive.
pub fn classify(error: &anyhow::Error) -> &'static str {
    // `anyhow::Error::downcast_ref` searches the context chain, unlike
    // `chain()`, which yields `&dyn Error` and would require `Failure` to
    // implement `Error` just to be looked up.
    error
        .downcast_ref::<Failure>()
        .map_or("request_failed", |failure| failure.code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Context};

    #[test]
    fn recovers_the_class_through_added_context() {
        // Errors pick up context as they travel up; the class has to survive it.
        let error = Err::<(), _>(anyhow!("the audience did not match"))
            .context(Failure::ClaimsRejected)
            .context("verifying the id_token")
            .unwrap_err();
        assert_eq!(classify(&error), "claims_rejected");
    }

    #[test]
    fn falls_back_to_the_silent_code() {
        let error = anyhow!("something the enclave has no class for");
        assert_eq!(classify(&error), "request_failed");
    }

    #[test]
    fn codes_are_distinct() {
        // They are matched on by name across three codebases, so a duplicate
        // would silently merge two causes into one.
        let all = [
            Failure::PolicyRejected,
            Failure::ProviderMismatch,
            Failure::CredentialBinding,
            Failure::JwksUnreachable,
            Failure::SignatureRejected,
            Failure::ClaimsRejected,
            Failure::AuthStale,
            Failure::SessionUnknown,
        ];
        let mut codes: Vec<_> = all.iter().map(|f| f.code()).collect();
        codes.sort_unstable();
        let total = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), total);
    }
}

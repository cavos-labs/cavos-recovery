# Security

Hardware-isolated, non-custodial social recovery for Cavos wallets (AWS Nitro Enclave).
This document is the threat-model note for `cavos-labs/cavos-recovery`. It is **not** a claim that the system removes all trusted parties.

## What this is (and is not)

Hardware-isolated social recovery lets a user who has lost every device sign in with a configured OIDC provider (Google, Apple, or Firebase email) and **authorize a new device signer**. Credential verification and the authorizing signature happen inside a measured AWS Nitro Enclave. The ID token is never handled in cleartext outside that enclave, including by Cavos.

It is **opt-in** per Cavos environment. It is **separate from Essential on-device recovery** (passkey, recovery code, or enrolled device), which does not use this enclave. Day-to-day wallet signing is the on-device / on-chain device signer path and does not depend on the enclave host being up.

## Trust boundary

**Trusted:** only `enclave/` — the measured Nitro workload.

**Assumed hostile by design:** the parent EC2 host, `relay/`, the Cavos control plane, and repository CI.

- The browser encrypts the job to a P-256 channel key taken **from inside** an AWS-signed attestation document, not from a relay-supplied JSON field alone.
- KMS releases the root sealing key only when the recipient attestation measures to a pinned PCR0; instance IAM credentials alone are not authority.
- Attestation `user_data` binds a document to one session (`sha256(session_id)`).

A compromise of relay or host is treated as **availability loss**, not credential disclosure or wallet recovery by the attacker.

## Protocol (summary)

1. **OpenSession** — Enclave generates an ephemeral P-256 channel key and returns an AWS Nitro attestation binding that key to the session.
2. **Browser** — Verifies attestation against the pinned PCR0 policy in `@cavos/kit`, then encrypts the job (including the ID token) to that key.
3. **RunJob** — Session key is single-use. OIDC verification, enroll (seal), or recover (unseal + authorize new device signer) run **inside** the enclave.
4. The enclave **does not** broadcast transactions or move funds. On-chain policy remains the final gate.

## What Cavos does not hold

| Asset | Held by Cavos / relay / host? |
| --- | --- |
| Day-to-day device signing keys | No |
| Cleartext OIDC ID token | No — plaintext only inside the enclave |
| Ability to move funds via this service | No |
| Root sealing key plaintext | No outside the enclave |

## Attestation and PCR0

PCR0 is the SHA-384 measurement of the enclave image.

- **Browser pin:** `@cavos/kit` `src/recovery/attestationDefaults.ts`
- **KMS pin:** `kms:RecipientAttestation:PCR0` on the root key policy (`infra/`)
- **Rebuild:** `enclave/scripts/build-enclave.sh` (reproducible). Independent rebuilds of the same source yield the same PCR0.

Browser pin and KMS condition must agree for a given release.

## Threat outcomes (by design)

| Threat | Expected outcome |
| --- | --- |
| Relay or EC2 host compromise | DoS / transport integrity only |
| Wrong PCR0 image | KMS deny; browser refuse |
| Session attestation replay | Fail session binding |
| Replayed RunJob | Unknown session (single-use claim) |
| Abuse of relay shared secret | Availability / abuse control only — not confidentiality |

## Residual risks (accepted or documented)

- Trust remains in the published measurement, AWS Nitro attestation PKI, and KMS PCR0 policy.
- Spot interruption or `host_count = 0`: enroll/recover unavailable; device signing unaffected.
- Caddy certificate material in S3 can be used to impersonate `enclave.cavos.xyz` toward the control plane (transport). That does **not** break attested encrypt or KMS PCR0.
- Root sealing key resides in enclave memory for the process lifetime; an enclave break is catastrophic for sealed records.

## Reporting

Security reports for this repository: contact Cavos (https://cavos.xyz) / `adrianvrj@cavos.xyz`.

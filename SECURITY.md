# Security

Hardware-isolated, non-custodial social recovery for Cavos wallets (AWS Nitro Enclave).
This document is the threat-model note for `cavos-labs/cavos-recovery`. It is **not** a claim that the system removes all trusted parties.

## What this is (and is not)

Hardware-isolated social recovery lets a user who has lost every device sign in with a configured identity provider (Google, Apple, GitHub, Telegram, or email) and **authorize a new device signer**. Credential verification and the release of the sealed wallet secret happen inside a measured AWS Nitro Enclave. An ID token is accepted only inside a job encrypted with the login key it names, so the token alone recovers nothing, whoever holds it.

It is **opt-in** per Cavos environment. It is **separate from Essential on-device recovery** (passkey, recovery code, or enrolled device), which does not use this enclave. Day-to-day wallet signing is the on-device / on-chain device signer path and does not depend on the enclave host being up.

## Trust boundary

**Trusted:** only `enclave/` — the measured Nitro workload.

**Assumed hostile by design:** the parent EC2 host, `relay/`, the Cavos control plane, and repository CI.

- The browser encrypts the job to a P-256 channel key taken **from inside** an AWS-signed attestation document, not from a relay-supplied JSON field alone.
- KMS releases the root sealing key only when the recipient attestation measures to a pinned PCR0; instance IAM credentials alone are not authority.
- The KMS key ARN and encryption context are compiled into the measured image, so the parent cannot make the enclave adopt a root key wrapped under a different key.
- Attestation `user_data` binds a document to one session (`sha256(session_id)`).
- Every login is bound to a key the client holds and cannot export. The OIDC `nonce` is `<app_id>.<base64url(SHA-256(login public key))>`, and the enclave accepts a token only in a job encrypted with that key (proof of possession, as in RFC 9449). Tokens the enclave issues for email, GitHub and Telegram carry the same binding, and an emailed code is redeemable only by the key that requested it.

A compromise of relay or host is treated as **availability loss**, not credential disclosure or wallet recovery by the attacker.

## Protocol (summary)

1. **OpenSession** — Enclave generates an ephemeral P-256 channel key and returns an AWS Nitro attestation binding that key to the session.
2. **Browser** — Verifies attestation against the release policy in `@cavos/kit`, then encrypts the job (including the ID token) to that key, using its login key as the client side of the channel.
3. **RunJob** — Session key is single-use. OIDC verification, the login-key check, enroll (seal), or recover (unseal and wrap to the new device) run **inside** the enclave.
4. The enclave **does not** broadcast transactions or move funds. On-chain policy remains the final gate.

## What Cavos does not hold

| Asset | Held by Cavos / relay / host? |
| --- | --- |
| Day-to-day device signing keys | No |
| Cleartext OIDC ID token | Yes for Google and Apple: the control plane redeems the authorization code. It is unusable without the client's login key. GitHub and Telegram codes are redeemed inside the enclave. |
| Login key | No — generated in the client and not exportable |
| Ability to move funds via this service | No |
| Root sealing key plaintext | No outside the enclave |

## Attestation and PCR0

PCR0 is the SHA-384 measurement of the enclave image.

- **Browser policy:** `@cavos/kit` `src/recovery/attestationDefaults.ts` accepts an image only when a signed release of this repository vouches for its PCR0, PCR1 and PCR2: a Sigstore attestation logged in Rekor, made by `.github/workflows/release.yml` on a `v<N>` tag, in the `release` deployment environment, at or above the kit's minimum version. The kit pins no measurement itself.
- **KMS pin:** `kms:RecipientAttestation:PCR0` on the root key policy (`infra/`)
- **Rebuild:** `enclave/scripts/build-enclave.sh` (reproducible). Independent rebuilds of the same source yield the same PCR0.

The KMS condition must name the PCR0 of a published release.

### Release governance

A release is accepted by every SDK, so who can publish one matters as much as who can change the KMS policy. A `v*` tag can only be created by a repository administrator and cannot be moved or deleted; the workflow refuses a commit that is not on `main`; the `release` environment deploys only from `v*` tags and requires a reviewer; published releases are immutable. The environment is recorded by Fulcio in the signing certificate and checked by the kit, so a workflow edited to skip it does not yield an accepted release.

## Threat outcomes (by design)

| Threat | Expected outcome |
| --- | --- |
| Relay or EC2 host compromise | DoS / transport integrity only |
| Wrong PCR0 image | KMS deny; browser refuse |
| Session attestation replay | Fail session binding |
| ID token or page state stolen from the browser | Unusable without the login key |
| Replayed RunJob | Unknown session (single-use claim) |
| Abuse of relay shared secret | Availability / abuse control only — not confidentiality |

## Residual risks (accepted or documented)

- Trust remains in the published measurement, AWS Nitro attestation PKI, and KMS PCR0 policy.
- Spot interruption or `host_count = 0`: enroll/recover unavailable; device signing unaffected.
- Caddy certificate material in S3 can be used to impersonate `enclave.cavos.xyz` toward the control plane (transport). That does **not** break attested encrypt or KMS PCR0.
- An AWS account administrator can rewrite the KMS key policy (`kms:Put*`) and thereby obtain the root sealing key. This is detected (EventBridge alerts on key-policy, grant, deletion and parameter changes) but not prevented. The planned fix is enclave-to-enclave key forwarding gated by M-of-N offline approval keys compiled into the image, with one immutable KMS key per release; it is deferred until approval keys can be held by more than one independent person.
- A repository administrator can change the rulesets and the `release` environment and then publish a release. Rekor records every release publicly; nothing yet enforces a waiting period or a second approver.
- The page that starts a login is trusted for that login. The login key lives in the Cavos vault frame, out of reach of the integrating page's scripts, but a page that is hostile from the start can run a login of its own with a key it holds and have the user complete it. Apps that need to exclude their own frontend should use passkey recovery, which the browser binds to the vault origin.
- The enclave cannot tell who started a provider login. A party able to receive the provider's redirect — the Cavos control plane — could start a login bound to its own key and, if the user completes it, recover that user's wallet. This is inherent to recovery by OAuth with a redirect operated by Cavos; it requires the user's participation and is limited to one user per attempt.
- Root sealing key resides in enclave memory for the process lifetime; an enclave break is catastrophic for sealed records.

## Reporting

Security reports for this repository: contact Cavos (https://cavos.xyz) / `adrianvrj@cavos.xyz`.

# Cavos hardware-isolated recovery

Social recovery for Cavos wallets, running in an AWS Nitro Enclave.

A user who has lost every device can sign in with Google (or Apple, or a
Firebase magic link) and authorise a new device signer. The credential is
verified — and the authorising signature produced — inside an enclave whose
exact code is published and measured. Nothing outside that enclave ever sees the
credential, including Cavos.

## Layout

| | |
|---|---|
| `enclave/` | the measured workload; the only trusted component |
| `relay/` | parent-side process that moves frames between the control plane and the enclave |
| `infra/` | terraform for the host, the KMS key, and the network |

## What is trusted

Only `enclave/`. Everything else — the relay, the EC2 host, the Cavos control
plane, this repository's CI — sits outside the trust boundary, and the design
assumes each of them is hostile:

- the user's ID token is encrypted **in the browser** to a P-256 key generated
  inside the enclave, and the browser takes that key from *inside* an
  AWS-signed attestation document rather than from any field a relay could
  substitute;
- the enclave's root sealing key is released by KMS only against an attestation
  measuring to a published PCR0, so the host's IAM credentials are not authority
  on their own — the measurement is;
- `user_data` in the attestation binds a document to one session, so a document
  minted for one user cannot be replayed for another.

A compromise of the relay or the host denies service. It does not read
credentials or recover a wallet.

## The measurement

`PCR0` is the SHA-384 of the enclave image. It appears in two places that must
agree, or browsers and KMS will disagree about which enclave is legitimate:

- `kit/src/recovery/attestationDefaults.ts` in the SDK — what browsers accept;
- the `kms:RecipientAttestation:PCR0` condition on the KMS key policy.

`enclave/scripts/build-enclave.sh` derives it, and is reproducible: two
independent builds of the same source produce the same value. That is what makes
the published measurement auditable rather than merely asserted — anyone can
rebuild and check.

```bash
cd enclave && ./scripts/build-enclave.sh --expect <pcr0>
```

## Deploying

See `infra/README.md`. In short: `terraform apply`, run `bootstrap-secrets.sh`,
build and upload the enclave image, point DNS at the Elastic IP.

## History

This service ran on Google Confidential Space until August 2026. That design
booted one confidential VM per recovery session, which measured at 49–134
seconds of VM boot for roughly two seconds of work and failed outright about 9%
of the time when no zone had SEV capacity. The Nitro enclave is long-lived, so a
session is two synchronous calls.

The pre-migration history is in `cavos-labs/cavos` under
`confidential-recovery/`, where the service used to live.

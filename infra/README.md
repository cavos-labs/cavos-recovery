# Enclave host infrastructure

One Graviton instance running the Cavos recovery enclave, plus the KMS key that
wraps its root sealing key.

## Credentials

The AWS CLI signs in with `aws login`, which stores a session under
`~/.aws/login/`. Terraform's provider is a Go SDK and does not understand that
format, so bridge it once per shell:

```bash
eval "$(aws configure export-credentials --format env)"
```

## Order of operations

The first apply and the secrets have a chicken-and-egg problem: the root key is
generated *by* the KMS key that terraform creates. So:

```bash
terraform init
terraform apply                 # creates the key, bucket, instance, placeholders
./bootstrap-secrets.sh          # replaces the placeholders with real values
```

`bootstrap-secrets.sh` is separate on purpose. Generating the root key in
terraform would write its plaintext into state, and state is a file that gets
copied to laptops and CI. The script uses `generate-data-key-without-plaintext`,
so the plaintext is created inside KMS and never exists anywhere else.

Then upload the artifacts and point DNS at the instance:

```bash
BUCKET=$(terraform output -raw artifacts_bucket)

cd ../enclave && ./scripts/build-enclave.sh      # note the PCR0 it prints
aws s3 cp build/enclave.eif "s3://$BUCKET/enclave.eif"

cd ../relay && cargo build --release --target aarch64-unknown-linux-gnu
aws s3 cp target/aarch64-unknown-linux-gnu/release/cavos-recovery-relay \
          "s3://$BUCKET/cavos-recovery-relay"
```

Finally, add an `A` record for `enclave.cavos.xyz` pointing at the
`elastic_ip` output, wherever cavos.xyz's DNS is hosted — there is no Route 53
zone for it. Caddy cannot obtain a certificate until that record resolves, so
the relay is unreachable over HTTPS until this is done.

## The measurement

`enclave_pcr0` is the security-critical variable. It appears in two places that
must agree:

- the KMS key policy here, which refuses to release the root key to anything
  measuring differently;
- `kit/src/recovery/attestationDefaults.ts` in the SDK, which is what browsers accept.

Re-derive it with `enclave/scripts/build-enclave.sh`, which is reproducible: two
independent builds of the same source produce the same value, so the published
measurement is auditable rather than merely asserted.

## Cost

| | |
|---|---|
| `c6g.large` on-demand | ~$50/month (~$30 with a 1-year Savings Plan) |
| Elastic IP | free while associated |
| KMS key | ~$1/month |
| Nitro Enclaves | no charge |
| Per recovery | $0 |

An ALB was considered and rejected: ~$16–20/month to terminate TLS for a single
backend, against $0 for Caddy with Let's Encrypt on the instance itself. Revisit
when a second instance is worth having.

## What is trusted

Only the enclave. The instance, this terraform, the relay, and the control plane
are all outside the trust boundary:

- the user's credential is encrypted in the browser to a key only the enclave
  holds, and the browser verifies an AWS-signed attestation before encrypting;
- the instance role's credentials cannot decrypt the root key on their own —
  the key policy requires an attestation the parent cannot produce.

A compromise of the host denies service. It does not read credentials.

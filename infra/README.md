# Enclave host infrastructure

One Graviton instance running the Cavos recovery enclave, plus the KMS key that
wraps its root sealing key.

## Turning it on and off

**The host is currently off.** `host_count` defaults to `0`, and that is a real
operating state rather than a broken one — see the trade-offs below.

### On

```bash
eval "$(aws configure export-credentials --format env)"   # see Credentials
terraform apply -var host_count=1
```

That is all. The enclave keeps no durable state: the wrapped root key is in
Parameter Store, the image and the relay binary in S3, the KMS key policy
untouched. A cold boot rebuilds the host from those, so there is nothing to
restore and no order to get right.

Allow about five minutes. The instance installs packages, claims the Elastic IP,
restores Caddy's certificate from S3, and starts the enclave. Then check all
three layers:

```bash
# 1. The relay is up, and answering means it reached the enclave over vsock.
curl -s https://enclave.cavos.xyz/health          # -> ok

# 2. The enclave measures to what @cavos/kit accepts. If these disagree,
#    browsers will refuse it and KMS will refuse to release the root key.
SECRET=$(aws ssm get-parameter --name /cavos-recovery/relay-secret \
  --with-decryption --region us-east-1 --query Parameter.Value --output text)
curl -s -X POST https://enclave.cavos.xyz/sessions \
  -H 'content-type: application/json' -H "x-cavos-relay-key: $SECRET" \
  -d "{\"session_id\":\"smoke-$(date +%s)\"}" | python3 -c '
import base64, json, sys
raw = base64.urlsafe_b64decode(json.load(sys.stdin)["attestation_document_b64"] + "==")
at = raw.find(b"\x00\x58\x30", raw.find(b"pcrs"))
print("PCR0", raw[at + 3 : at + 51].hex())'
```

Compare that against `enclave_pcr0` in `variables.tf` **and** the list in
`kit/src/recovery/attestationDefaults.ts`. All three must agree.

### Off

```bash
terraform apply          # host_count defaults to 0
```

While it is off there is no enrolment and no recovery. Wallets keep signing:
that is the device signer against the on-chain contract and has never involved
this host. No funds are at risk either way.

### What it costs

|            | per month |
| ---------- | --------- |
| On         | ~$27      |
| Off        | ~$6.60    |

Most of the residual is the Elastic IP and the KMS keys. Both are worth keeping:
releasing the address means re-pointing DNS and re-issuing a certificate against
Let's Encrypt's five-per-week limit, and the root sealing key wraps the key every
recovery record is sealed with — **deleting it makes every enrolled wallet
permanently unrecoverable.** It is the one resource here whose removal cannot be
undone.

### Things that have bitten us

- **`-var host_count=1` is not sticky.** It applies to that command only, so a
  later bare `terraform apply` turns the host back off. To leave it running,
  change the default in `variables.tf` and commit it.
- **The relay binary is built for the host, not for your laptop.** Build it
  static so it does not depend on Amazon Linux's glibc:

  ```bash
  cd ../relay && docker run --rm -v "$PWD":/w -w /w rust:1-alpine sh -c \
    'apk add --no-cache musl-dev >/dev/null && cargo build --release --locked \
     --target aarch64-unknown-linux-musl'
  ```

- **Changing PCR0 is half a deploy.** The new EIF has to be in S3 in the same
  step, or the enclave boots and dies unable to unwrap the root key — and
  `@cavos/kit` must already accept the new measurement, because the browser
  checks it before KMS ever sees anything. See *The measurement*.
- **Diagnostics are off by default.** The enclave names the check that refused a
  request, but the relay's outbound forwarder logs at debug. If recovery is
  failing and you need to know whether the enclave is reaching a provider's
  JWKS at all:

  ```bash
  ASG=$(terraform output -raw autoscaling_group)
  ID=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$ASG" \
        --query 'AutoScalingGroups[0].Instances[0].InstanceId' --output text --region us-east-1)
  aws ssm send-command --instance-ids "$ID" --document-name AWS-RunShellScript --region us-east-1 \
    --parameters 'commands=["mkdir -p /etc/systemd/system/cavos-relay.service.d","printf \"[Service]\\nEnvironment=RUST_LOG=info,cavos_recovery_relay::sni=debug\\n\" > /etc/systemd/system/cavos-relay.service.d/debug.conf","systemctl daemon-reload","systemctl restart cavos-relay"]'
  ```

  Restarting the relay restarts the enclave with it — `cavos-enclave.service`
  requires it. And the override lives on the instance, so it does not survive a
  replacement.

## Credentials

The AWS CLI signs in with `aws login`, which stores a session under
`~/.aws/login/`. Terraform's provider is a Go SDK and does not understand that
format, so bridge it once per shell:

```bash
eval "$(aws configure export-credentials --format env)"
```

## First-time setup

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

Measured, not estimated — the figures below are what the account actually
billed over 13–17 August 2026.

| | per month |
| --- | --- |
| Spot `c7g.large` | ~$19 |
| Public IPv4 (the Elastic IP) | $3.65 |
| KMS, three keys across two regions | $2.94 |
| EBS, 10 GiB gp3 | $0.76 |
| S3 artifacts and requests | ~$0.15 |
| Nitro Enclaves | no charge |
| Per recovery | $0 |
| **Running** | **~$27** |
| **Off** (`host_count = 0`) | **~$6.60** |

Two notes on lines that surprise people:

- **The Elastic IP is not free.** AWS has charged for every public IPv4 address
  since February 2024, whether or not it is associated. It is kept anyway; see
  *Turning it on and off*.
- **One of the KMS keys is billed twice.** `mrk-04508567…` is a multi-region key
  belonging to IAM Identity Center, with a replica in us-west-2 that bills
  separately. It is not this service's, and not this service's to delete.

Buying the host on spot rather than on demand is where most of the saving came
from: $1.80/day on an on-demand `c6g.large` became $0.63/day on spot, a 65% cut,
for a workload that holds no durable state and can be rebuilt from S3 and
Parameter Store on every boot.

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

#!/usr/bin/env bash
#
# Bring up the enclave host.
#
# Three processes cooperate, and only one of them is trusted:
#
#   enclave      the measured workload; holds every secret
#   vsock-proxy  gives the enclave outbound TLS to KMS and provider JWKS,
#                relaying ciphertext it cannot read
#   relay        accepts HTTPS from the control plane and forwards frames
#
# Everything here runs on the untrusted parent. A compromise of this script can
# deny service; it cannot read a user's credential or impersonate the enclave,
# because the browser checks an AWS-signed attestation before encrypting
# anything, and KMS refuses to release the root key without the same proof.

set -euxo pipefail

REGION="${region}"
HOSTNAME="${hostname}"
ARTIFACTS_BUCKET="${artifacts_bucket}"
ENCLAVE_CPU_COUNT="${enclave_cpu_count}"
ENCLAVE_MEMORY_MIB="${enclave_memory_mib}"

dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel amazon-ssm-agent jq

# The allocator reserves CPUs and memory for enclaves at boot. It has to be
# configured before the service starts, and a change needs a reboot.
cat >/etc/nitro_enclaves/allocator.yaml <<EOF
---
memory_mib: $ENCLAVE_MEMORY_MIB
cpu_count: $ENCLAVE_CPU_COUNT
EOF
systemctl enable --now nitro-enclaves-allocator.service
systemctl enable --now amazon-ssm-agent

mkdir -p /opt/cavos
aws s3 cp "s3://$ARTIFACTS_BUCKET/enclave.eif" /opt/cavos/enclave.eif --region "$REGION"
aws s3 cp "s3://$ARTIFACTS_BUCKET/cavos-recovery-relay" /opt/cavos/relay --region "$REGION"
chmod +x /opt/cavos/relay

# ---------------------------------------------------------------------------
# Outbound for the enclave
# ---------------------------------------------------------------------------
# The enclave has no network device. vsock-proxy opens a TCP connection to a
# fixed allow-listed host on its behalf. TLS is negotiated *inside* the enclave,
# so this process moves ciphertext: it cannot read the KMS traffic and cannot
# impersonate accounts.google.com, because it has no certificate for it.
cat >/etc/nitro_enclaves/vsock-proxy.yaml <<EOF
allowlist:
- {address: kms.$REGION.amazonaws.com, port: 443}
- {address: accounts.google.com, port: 443}
- {address: www.googleapis.com, port: 443}
- {address: appleid.apple.com, port: 443}
- {address: securetoken.google.com, port: 443}
EOF

cat >/etc/systemd/system/cavos-vsock-kms.service <<EOF
[Unit]
Description=vsock proxy: enclave -> KMS
After=nitro-enclaves-allocator.service

[Service]
ExecStart=/usr/bin/vsock-proxy 8000 kms.$REGION.amazonaws.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# One proxy per port, and the enclave maps every provider host to this one. The
# hostname below is only the default target; the enclave preserves SNI and the
# Host header, so the connection is validated against the real name inside.
cat >/etc/systemd/system/cavos-vsock-oidc.service <<EOF
[Unit]
Description=vsock proxy: enclave -> identity provider JWKS
After=nitro-enclaves-allocator.service

[Service]
ExecStart=/usr/bin/vsock-proxy 8001 www.googleapis.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# The enclave
# ---------------------------------------------------------------------------
# The enclave is started with no configuration at all; it pulls what it needs
# from the relay over vsock once running. See the comment in the start script.
cat >/usr/local/bin/cavos-start-enclave <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

CPU_COUNT="$1"; MEMORY_MIB="$2"

# No credentials or configuration are passed here, because `nitro-cli
# run-enclave` has no way to accept them: an enclave's environment is fixed at
# image build time. Baking in a rotating credential — or the wrapped root key —
# would also change PCR0 on every rotation, which would break every browser
# pinning the published measurement.
#
# Instead the enclave connects back to the relay's vsock configuration port on
# startup and asks. See `protocol::EnclaveConfig` for why taking configuration
# from an untrusted parent is safe.
exec nitro-cli run-enclave \
  --eif-path /opt/cavos/enclave.eif \
  --cpu-count "$CPU_COUNT" \
  --memory "$MEMORY_MIB" \
  --enclave-cid 16
SCRIPT
chmod +x /usr/local/bin/cavos-start-enclave

cat >/etc/systemd/system/cavos-enclave.service <<EOF
[Unit]
Description=Cavos confidential recovery enclave
# The relay serves this enclave's configuration over vsock, so it has to be
# listening first. That inverts the obvious dependency: the relay does not need
# the enclave to bind its own ports, but the enclave cannot start without the
# relay's configuration service.
After=cavos-vsock-kms.service cavos-vsock-oidc.service cavos-relay.service
Requires=cavos-vsock-kms.service cavos-vsock-oidc.service cavos-relay.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/cavos-start-enclave $ENCLAVE_CPU_COUNT $ENCLAVE_MEMORY_MIB
ExecStop=/usr/bin/nitro-cli terminate-enclave --all
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# The relay
# ---------------------------------------------------------------------------
cat >/etc/systemd/system/cavos-relay.service <<EOF
[Unit]
Description=Cavos recovery relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=/bin/bash -c 'aws ssm get-parameter --name ${relay_secret_param} --with-decryption --region $REGION --query Parameter.Value --output text > /run/cavos-relay-secret'
ExecStart=/bin/bash -c 'CAVOS_RELAY_SHARED_SECRET=\$(cat /run/cavos-relay-secret) CAVOS_ENCLAVE_CID=16 CAVOS_RELAY_BIND=127.0.0.1:8080 AWS_REGION=$REGION CAVOS_ROOT_KEY_PARAM=${root_key_param} /opt/cavos/relay'
Restart=always
RestartSec=5
# The relay holds nothing worth protecting, but there is no reason to give it
# the whole filesystem. It stays root because it reads the secret written by
# ExecStartPre and shells out to the AWS CLI for Parameter Store.
ProtectSystem=full
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------
# Caddy obtains and renews a Let's Encrypt certificate on its own. It is used
# instead of an ALB because an ALB costs ~$16-20/month, which is a third again
# of the instance, to terminate TLS for a single backend.
dnf install -y 'dnf-command(copr)' || true
dnf copr enable -y @caddy/caddy epel-9-aarch64 || true
dnf install -y caddy || {
  curl -sSfL "https://github.com/caddyserver/caddy/releases/latest/download/caddy_linux_arm64.tar.gz" \
    | tar -xz -C /usr/local/bin caddy
}

cat >/etc/caddy/Caddyfile <<EOF
$HOSTNAME {
	reverse_proxy 127.0.0.1:8080
}
EOF
systemctl enable --now caddy

systemctl daemon-reload
systemctl enable --now cavos-vsock-kms cavos-vsock-oidc cavos-relay cavos-enclave

# The enclave

The measured workload. This is the only trusted component in the system, and the
only one whose source is pinned by a published measurement.

It runs as a long-lived AWS Nitro Enclave, answering two requests over vsock:

```
OpenSession → generate a P-256 channel key, attest to it, return the document
RunJob      → decrypt the job with that session's key, verify the OIDC
              credential, then sign an authorisation or seal a record
```

Sessions are single-use: `RunJob` removes the channel key, so a replayed job
finds nothing.

## What it can and cannot see

The enclave has no network device and no persistent storage. Its only channels
are vsock to the parent instance:

| port | direction | purpose |
|---|---|---|
| 5005 | in | requests from the relay |
| 5006 | out | fetches its own configuration at startup |
| 5007 | out | reports a startup failure so the parent can log it |
| 8000/8001 | out | TLS to KMS and to provider JWKS, via `vsock-proxy` |

TLS on the outbound paths terminates *inside* the enclave, so the parent relays
ciphertext it cannot read and cannot impersonate `accounts.google.com` — it has
no certificate for it.

Configuration arrives over vsock rather than as environment variables because
`nitro-cli run-enclave` cannot set them, and baking a rotating credential into
the image would change PCR0 on every rotation.

## Building

```bash
./scripts/build-enclave.sh                  # build and print measurements
./scripts/build-enclave.sh --expect <pcr0>  # ...and fail if it differs
```

The build is reproducible. Base images are pinned by digest, `SOURCE_DATE_EPOCH`
and BuildKit timestamp rewriting remove the wall-clock timestamp that otherwise
changes the measurement on every build, and the nitro-cli version is checked
because the tool itself is an input to the image.

## Tests

```bash
cargo test
```

`crypto.rs` carries cross-language vectors shared with the SDK; if those fail,
the enclave and the browser have stopped agreeing about what they are signing.

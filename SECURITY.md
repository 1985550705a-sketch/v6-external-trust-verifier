# Security boundary

- No secrets are required for signing; future signing is Sigstore keyless.
- Only GitHub-hosted standard runners are permitted.
- Raw V6 evidence must remain off-repository.
- Workflow execution remains disabled until immutable repository IDs, workflow SHA,
  vendored drand verifier SHA, and exact dependency provenance are frozen.
- A trust-domain PASS does not itself increment Native 0/6.

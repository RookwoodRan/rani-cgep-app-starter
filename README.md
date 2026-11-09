# Acme Health: continuous compliance pipeline (CGE-P capstone)

Fork of `GRCEngClub/cgep-app-starter`. The Patient Intake API from the starter is still here and runnable; this repo adds a Terraform GRC baseline, six OPA/Rego policies, a GitHub Actions pipeline that gates, applies, signs and stores evidence, and an OSCAL package. Framework: **CMMC Level 2 (NIST SP 800-171)**. Reasoning, trade-offs and gaps are in [WRITEUP.md](WRITEUP.md).

## Layout

| Path | What it is |
|---|---|
| `terraform/` | Starter stack plus the baseline: KMS keys, Object Lock evidence vault, CloudTrail, gap fixes |
| `bootstrap/` | One-time setup: state bucket, GitHub OIDC, plan and apply roles |
| `policies/` | Six Rego policies, shared helper, and tests (`policies/tests/`) |
| `scripts/` | `policy-gate.sh`, `verify-evidence.sh`, `build_oscal.py`, `validate-oscal.sh` |
| `.github/workflows/grc-gate.yml` | The pipeline |
| `oscal/` | Component definition and profile |
| `evidence/verification/` | A copy of one signed run, for offline verification |

## Running the workload

The Patient Intake API itself is unchanged from the starter (see [WORKLOAD.md](WORKLOAD.md) and [GAPS.md](GAPS.md)). Deploy and smoke-test it with:

```
make creds  AWS_PROFILE=<your-sandbox-profile>
make deploy AWS_PROFILE=<your-sandbox-profile>
make test   AWS_PROFILE=<your-sandbox-profile>
```

The expected `make test` response is `{"submission_id": "...", "status": "received"}`. The pipeline deploys this stack from `main`, so a grader does not need to deploy anything to check the evidence below.

## How to verify

**1. Policies and tests** (35 tests, 6 policies; needs [conftest](https://www.conftest.dev/) or [opa](https://www.openpolicyagent.org/)):

```
conftest verify --policy policies
opa test ./policies
```

**2. Green and red pull requests.** PR #1 passed the gate and merged; PR #2 was blocked by the gate (`[MP.L2-3.8.9]`, GAP-04 reintroduced) and is left open on purpose. The `main` branch ruleset requires the `grc-gate` check.

**3. Signed evidence, offline.** The bundle for the run that did a real apply (`42706911885`) is committed. You need [cosign](https://github.com/sigstore/cosign) v2.x and no AWS access:

```
cd evidence/verification/run-42706911885
echo "$(cat evidence-42706911885-*.tar.gz.sha256)  $(ls evidence-42706911885-*.tar.gz)" | sha256sum -c -
cosign verify-blob \
  --bundle evidence-42706911885-*.tar.gz.sig.bundle \
  --certificate-identity-regexp '^https://github.com/RookwoodRan/rani-cgep-app-starter/.github/workflows/grc-gate.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  evidence-42706911885-*.tar.gz
```

The first command prints `OK`; the second prints `Verified OK` (signature, Fulcio certificate and Rekor entry).

**4. Full chain of custody, with vault access.** The vault is private. With read access to it, the script also checks that Object Lock retention is still active (it runs until 2026-12-09 for this run) and prints `CHAIN INTACT`:

```
bash scripts/verify-evidence.sh 42706911885
```

Other runs: `42547179941` (green PR), `42550227346` (red PR, blocked), `42548157532` (first merge).

**5. OSCAL.** The component's `control-implementation.source` is the NIST SP 800-171 Rev 3 OSCAL catalog.

```
bash scripts/validate-oscal.sh          # trestle validate: both files should print VALID
python scripts/build_oscal.py --check   # needs vault access: every evidence link resolves and hashes match
```

**6. Reintroduce a gap and watch the gate fire.** In `terraform/hardening.tf`, change versioning `status` from `"Enabled"` to `"Suspended"`, then:

```
cd terraform && terraform plan -out=tfplan && cd ..
bash scripts/policy-gate.sh --workspace terraform
```

Expected: `policy-gate: FAIL` with `[MP.L2-3.8.9] aws_s3_bucket.uploads must have versioning enabled…`. Revert the change afterwards. (This needs AWS credentials for the plan; PR #2 shows the same result in CI.)

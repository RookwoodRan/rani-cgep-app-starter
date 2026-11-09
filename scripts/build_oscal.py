#!/usr/bin/env python3
"""Build the OSCAL package for the Acme Health intake stack.

Writes:
  oscal/components/acme-health-intake.json   component definition (what we built, and the proof)
  oscal/profiles/cge-p-minimum.json          profile (the controls we claim)

Everything that can be looked up is looked up, not typed:
  * Terraform addresses and ARNs come from `terraform show -json` (real state)
  * evidence objects, versions and hashes come from the receipts the pipeline wrote to the vault

Usage:
  python scripts/build_oscal.py --green-run 42548157532 --red-run 42550227346
  python scripts/build_oscal.py --check          # confirm every evidence link resolves and its hash matches
"""
import argparse
import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

REGION = "ca-central-1"
VAULT = "acme-health-intake-evidence-08fa0596"
REPO = "https://github.com/RookwoodRan/rani-cgep-app-starter"
CATALOG = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json"
OSCAL_VERSION = "1.2.1"
COMPONENT_FILE = Path("oscal/components/acme-health-intake.json")
PROFILE_FILE = Path("oscal/profiles/cge-p-minimum.json")

# CMMC Level 2 practice -> NIST SP 800-171 Rev 3 requirement (catalog id) -> what implements it.
CONTROLS = [
    {
        "cmmc": "SC.L2-3.13.11",
        "id": "SP_800_171_03.13.11",
        "status": "implemented",
        "gaps": "GAP-01, GAP-02",
        "description": (
            "PHI at rest is encrypted with a customer-managed KMS key with annual rotation: "
            "the S3 uploads bucket (SSE-KMS) and the DynamoDB intake table. "
            "The key is under customer control, not the AWS-owned or AWS-managed default."
        ),
        "addresses": [
            "aws_kms_key.phi",
            "aws_s3_bucket_server_side_encryption_configuration.uploads",
            "aws_dynamodb_table.intake",
        ],
        "policies": ["policies/sc13_11_s3_cmk.rego", "policies/sc13_11_dynamodb_cmk.rego"],
        "evidence": ["green"],
    },
    {
        "cmmc": "SC.L2-3.13.8",
        "id": "SP_800_171_03.13.08",
        "status": "implemented",
        "gaps": "GAP-03",
        "description": (
            "Every S3 bucket carries a bucket policy that denies any request not made over TLS "
            "(aws:SecureTransport = false), protecting CUI/PHI in transit to and from storage."
        ),
        "addresses": [
            "aws_s3_bucket_policy.uploads_tls_only",
            "aws_s3_bucket_policy.evidence_tls_only",
            "aws_s3_bucket_policy.trail",
        ],
        "policies": ["policies/sc13_8_tls.rego"],
        "evidence": ["green"],
    },
    {
        "cmmc": "MP.L2-3.8.9",
        "id": "SP_800_171_03.08.09",
        "status": "partial",
        "gaps": "GAP-04",
        "description": (
            "S3 versioning is enabled on the uploads bucket and the evidence vault so overwritten or "
            "deleted PHI is recoverable, and the stored versions are encrypted with the customer-managed key. "
            "This is a partial fit: the Rev 3 requirement is about cryptographic protection of backups, "
            "and no separate backup service is deployed."
        ),
        "addresses": [
            "aws_s3_bucket_versioning.uploads",
            "aws_s3_bucket_versioning.evidence",
        ],
        "policies": ["policies/mp3_8_9_versioning.rego"],
        "evidence": ["green", "red"],
        "red_text": "Pipeline run in which a regression suspending uploads versioning was blocked by this policy.",
    },
    {
        "cmmc": "SC.L2-3.13.1",
        "id": "SP_800_171_03.13.01",
        "status": "implemented",
        "gaps": "GAP-05",
        "description": (
            "The intake Lambda runs inside the VPC's private subnets with a security group that has no inbound "
            "rules and only HTTPS egress to the S3 and DynamoDB gateway endpoints. There is no internet route "
            "and no NAT gateway."
        ),
        "addresses": [
            "aws_lambda_function.intake",
            "aws_security_group.lambda",
            "aws_vpc_endpoint.s3",
            "aws_vpc_endpoint.dynamodb",
        ],
        "policies": ["policies/sc13_1_lambda_vpc.rego"],
        "evidence": ["green"],
    },
    {
        "cmmc": "AC.L2-3.1.5",
        "id": "SP_800_171_03.01.05",
        "status": "implemented",
        "gaps": "GAP-07",
        "description": (
            "The Lambda execution role is limited to dynamodb:PutItem on the intake table, s3:PutObject under "
            "uploads/, and the KMS actions needed for the data key. No service-wide wildcards."
        ),
        "addresses": ["aws_iam_role.lambda", "aws_iam_role_policy.lambda_inline"],
        "policies": ["policies/ac3_1_5_least_privilege.rego"],
        "evidence": ["green"],
    },
]


def det_uuid(name: str) -> str:
    """Stable, valid version-4 UUID derived from a name (so rebuilding does not churn the diff)."""
    digest = hashlib.sha256(f"acme-health-intake-oscal:{name}".encode()).digest()[:16]
    return str(uuid.UUID(bytes=digest, version=4))


def run(cmd):
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"command failed: {' '.join(cmd)}\n{res.stderr.strip()}")
    return res.stdout


def load_state(path):
    raw = Path(path).read_text() if path else run(["terraform", "-chdir=terraform", "show", "-json"])
    resources = {}

    def walk(module):
        for r in module.get("resources", []):
            resources[r["address"]] = r.get("values", {})
        for child in module.get("child_modules", []):
            walk(child)

    walk(json.loads(raw)["values"]["root_module"])
    return resources


def read_receipt(run_id):
    out = run(["aws", "s3", "cp", f"s3://{VAULT}/runs/{run_id}/receipt.json", "-", "--region", REGION])
    receipt = json.loads(out)
    if receipt["vault"] != VAULT or str(receipt["run_id"]) != str(run_id):
        sys.exit(f"receipt for run {run_id} does not match this vault/run")
    return receipt


def evidence_resource(label, run_id, receipt):
    key = receipt["bundle_key"]
    uri = f"s3://{VAULT}/{key}"
    return {
        "uuid": det_uuid(f"evidence-{label}-{run_id}"),
        "title": f"Signed pipeline evidence bundle, run {run_id}",
        "description": (
            f"grc-gate run {run_id} at commit {receipt['commit']}: terraform plan, Conftest results, run metadata. "
            "Signed keyless with Cosign (Sigstore) and stored under Object Lock. "
            "Verify with: bash scripts/verify-evidence.sh " + str(run_id)
        ),
        "props": [
            {"name": "s3-version-id", "value": receipt["version_id"]},
            {"name": "github-run", "value": f"{REPO}/actions/runs/{run_id}"},
        ],
        "rlinks": [
            {
                "href": uri,
                "media-type": "application/gzip",
                "hashes": [{"algorithm": "SHA-256", "value": receipt["sha256"]}],
            },
            {"href": uri + ".sig.bundle", "media-type": "application/json"},
            {"href": f"s3://{VAULT}/runs/{run_id}/receipt.json", "media-type": "application/json"},
        ],
    }


def build(args):
    state = load_state(args.state_json)
    receipts = {"green": (args.green_run, read_receipt(args.green_run)), "red": (args.red_run, read_receipt(args.red_run))}
    resources = {label: evidence_resource(label, rid, rc) for label, (rid, rc) in receipts.items()}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

    requirements = []
    for c in CONTROLS:
        props = [
            {"name": "implementation-status", "value": c["status"]},
            {"name": "cmmc-practice", "value": c["cmmc"]},
            {"name": "starter-gap", "value": c["gaps"]},
        ]
        for addr in c["addresses"]:
            if addr not in state:
                sys.exit(f"{addr} is not in the Terraform state; fix CONTROLS or apply first")
            vals = state[addr]
            props.append({"name": "terraform-address", "value": addr})
            ident = vals.get("arn") or vals.get("id")
            if ident:
                props.append({"name": "arn" if vals.get("arn") else "resource-id", "value": str(ident)})
        for pol in c["policies"]:
            if not Path(pol).exists():
                sys.exit(f"policy file {pol} not found (run from the repo root)")
            props.append({"name": "rego-policy", "value": pol})

        links = [
            {
                "href": "#" + resources[label]["uuid"],
                "rel": "evidence",
                "text": c.get("red_text") if label == "red" else
                "Signed pipeline evidence: terraform plan and policy-gate results from the merge to main.",
            }
            for label in c["evidence"]
        ]
        requirements.append(
            {
                "uuid": det_uuid(f"req-{c['id']}"),
                "control-id": c["id"],
                "description": c["description"],
                "props": props,
                "links": links,
            }
        )

    component = {
        "component-definition": {
            "uuid": det_uuid("component-definition"),
            "metadata": {
                "title": "Acme Health Patient Intake API: GRC baseline",
                "last-modified": now,
                "version": "1.0.0",
                "oscal-version": OSCAL_VERSION,
                "remarks": "Claims are limited to the five practices listed; GAP-06 and GAP-08 from GAPS.md are not addressed.",
            },
            "components": [
                {
                    "uuid": det_uuid("component"),
                    "type": "software",
                    "title": "acme-health-intake",
                    "description": (
                        "Patient intake API on AWS (API Gateway, Lambda, DynamoDB, S3) in ca-central-1, with a "
                        "Terraform GRC baseline, OPA/Rego policy gate, and a signed evidence pipeline."
                    ),
                    "purpose": "Process patient intake submissions with controls enforced as code.",
                    "props": [{"name": "source-repository", "value": REPO}],
                    "control-implementations": [
                        {
                            "uuid": det_uuid("control-implementation"),
                            "source": CATALOG,
                            "description": (
                                "CMMC Level 2 practices, expressed as the NIST SP 800-171 Rev 3 requirements "
                                "they are drawn from."
                            ),
                            "implemented-requirements": requirements,
                        }
                    ],
                }
            ],
            "back-matter": {"resources": list(resources.values())},
        }
    }

    profile = {
        "profile": {
            "uuid": det_uuid("profile"),
            "metadata": {
                "title": "CGE-P minimum control selection: CMMC Level 2 on NIST SP 800-171 Rev 3",
                "last-modified": now,
                "version": "1.0.0",
                "oscal-version": OSCAL_VERSION,
            },
            "imports": [{"href": CATALOG, "include-controls": [{"with-ids": [c["id"] for c in CONTROLS]}]}],
            "merge": {"as-is": True},
        }
    }

    for path, doc in ((COMPONENT_FILE, component), (PROFILE_FILE, profile)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, indent=2) + "\n")
        print(f"wrote {path}")


def check():
    doc = json.loads(COMPONENT_FILE.read_text())["component-definition"]
    bad = 0
    for res in doc["back-matter"]["resources"]:
        for link in res["rlinks"]:
            bucket, key = link["href"][len("s3://"):].split("/", 1)
            run(["aws", "s3api", "head-object", "--bucket", bucket, "--key", key, "--region", REGION])
            msg = f"OK   exists  {link['href']}"
            if "hashes" in link:
                stored = run(["aws", "s3", "cp", f"s3://{bucket}/{key}.sha256", "-", "--region", REGION]).strip()
                if stored != link["hashes"][0]["value"]:
                    msg = f"FAIL hash mismatch  {link['href']}"
                    bad += 1
                else:
                    msg += "  (sha256 matches)"
            print(msg)
    # every evidence link in a requirement must point at a real back-matter resource
    ids = {r["uuid"] for r in doc["back-matter"]["resources"]}
    for comp in doc["components"]:
        for ci in comp["control-implementations"]:
            for req in ci["implemented-requirements"]:
                for link in req.get("links", []):
                    if link["href"].lstrip("#") not in ids:
                        print(f"FAIL dangling evidence link in {req['control-id']}: {link['href']}")
                        bad += 1
    print("EVIDENCE LINKS OK" if not bad else f"{bad} problem(s)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--green-run", help="run id of the merge-to-main pipeline run")
    ap.add_argument("--red-run", help="run id of the blocked (red) pipeline run")
    ap.add_argument("--state-json", help="use this `terraform show -json` file instead of running terraform")
    ap.add_argument("--check", action="store_true", help="verify evidence links and hashes against the vault")
    a = ap.parse_args()
    if a.check:
        check()
    elif a.green_run and a.red_run:
        build(a)
    else:
        ap.error("give --green-run and --red-run, or --check")

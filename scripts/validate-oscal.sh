#!/usr/bin/env bash
# scripts/validate-oscal.sh
# Validates the committed OSCAL files with trestle and records the result.
# Needs: pip install compliance-trestle. Run from the repo root.
set -euo pipefail

command -v trestle >/dev/null 2>&1 && TRESTLE="trestle" || TRESTLE="python -m trestle"
OUT="evidence/oscal/trestle-validate.txt"
mkdir -p evidence/oscal .trestle-work

# trestle wants its own folder layout; author there, copy from the committed files.
cd .trestle-work
[ -d .trestle ] || $TRESTLE init >/dev/null
mkdir -p component-definitions/acme-health-intake profiles/cge-p-minimum
cp ../oscal/components/acme-health-intake.json component-definitions/acme-health-intake/component-definition.json
cp ../oscal/profiles/cge-p-minimum.json profiles/cge-p-minimum/profile.json

{
  echo "trestle: $($TRESTLE version 2>&1 | tail -1)"
  $TRESTLE validate -f component-definitions/acme-health-intake/component-definition.json
  $TRESTLE validate -f profiles/cge-p-minimum/profile.json
} 2>&1 | tee "../$OUT"

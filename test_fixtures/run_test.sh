#!/bin/sh
# Runs the real scanner.py against a compliant triple of exports and a
# deliberately broken triple, asserting specific check_ids fire by id.
set -e
cd "$(dirname "$0")/.."

OUT=/tmp/entra_test_$$
mkdir -p "$OUT"
REF="2026-11-18T00:00:00Z"

run() {
  label="$1"
  python3 scanner.py \
    --ca-policies "test_fixtures/${label}_ca_policies.json" \
    --user-registrations "test_fixtures/${label}_user_registrations.json" \
    --role-assignments "test_fixtures/${label}_role_assignments.json" \
    --reference-date "$REF" \
    --json "$OUT/$label.json" --fail-on any > "$OUT/$label.txt" 2>&1
  echo $? > "$OUT/$label.exit"
}

assert_exit() {
  label="$1"; expected="$2"
  actual=$(cat "$OUT/$label.exit")
  [ "$actual" = "$expected" ] && echo "PASS: $label exit code $actual" \
    || { echo "FAIL: $label expected exit $expected, got $actual"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

assert_fail() {
  label="$1"; check_id="$2"
  python3 -c "
import json, sys
findings = json.load(open('$OUT/$label.json'))
sys.exit(0 if any(f['check_id'] == '$check_id' for f in findings) else 1)
" && echo "PASS: $label -> $check_id fired" \
  || { echo "FAIL: $label -> $check_id did not fire"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

echo "== Compliant =="
set +e; run compliant; set -e
cat "$OUT/compliant.txt"
assert_exit compliant 0
python3 -c "
import json, sys
findings = json.load(open('$OUT/compliant.json'))
sys.exit(0 if len(findings) == 0 else 1)
" && echo "PASS: compliant produced zero findings" \
  || { echo "FAIL: compliant unexpectedly produced findings"; rm -rf "$OUT"; exit 1; }

echo
echo "== Noncompliant =="
set +e; run noncompliant; set -e
cat "$OUT/noncompliant.txt"
assert_exit noncompliant 1
for cid in ENTRA-1 ENTRA-2 ENTRA-3 ENTRA-4 ENTRA-5 ENTRA-6 ENTRA-7; do
  assert_fail noncompliant "$cid"
done

rm -rf "$OUT"
echo
echo "All tests passed."

#!/usr/bin/env bash
# Run the published container image's documented offline commands.
#
# This tests the image that was actually pushed, not a local build: a release
# must not ship an entrypoint, user, or architecture that cannot execute the
# documented CLI. Each command below asserts its exit code and, where the
# command prints a result, that the result is present.
#
# Network commands (simulate, submit) are excluded on purpose. They need an RPC
# endpoint and, for submit, a funded source account; a release gate must not
# depend on testnet being reachable. Their client code is covered by the Go test
# suite and the e2e workflow.
#
# Usage:
#   scripts/smoke-image.sh --image ghcr.io/owner/repo:v0.1.0 --platform linux/amd64
set -euo pipefail

image=""
platform=""
while [ $# -gt 0 ]; do
  case "$1" in
    --image) image="${2:-}"; shift 2 ;;
    --platform) platform="${2:-}"; shift 2 ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "smoke-image: unknown argument $1" >&2; exit 2 ;;
  esac
done
if [ -z "$image" ] || [ -z "$platform" ]; then
  echo "smoke-image: --image and --platform are required" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vector="$root/testdata/vectors/v2_single_testnet.json"
if [ ! -f "$vector" ]; then
  echo "smoke-image: missing vector $vector" >&2
  exit 1
fi

json_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)[sys.argv[2]])
PY
}

entry="$(json_field "$vector" unsigned_entry_xdr)"
signed="$(json_field "$vector" signed_entry_xdr)"
valid_until="$(json_field "$vector" valid_until_ledger)"

run() {
  docker run --rm --platform "$platform" "$image" "$@"
}

fail() {
  echo "smoke-image: $platform: $*" >&2
  exit 1
}

echo "== $platform: --version"
version="$(run --version)"
[ -n "$version" ] || fail "--version printed nothing"
case "$version" in
  *soroauth*) ;;
  *) fail "--version did not identify soroauth: $version" ;;
esac

echo "== $platform: inspect"
inspect="$(run inspect --entry "$entry" --json)"
delegate="$(python3 - "$inspect" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
if doc.get("credential_type") != "address_v2":
    raise SystemExit(f"inspect credential_type = {doc.get('credential_type')!r}, want address_v2")
if not doc.get("address"):
    raise SystemExit("inspect did not report the credential address")
print(doc["address"])
PY
)"

echo "== $platform: payload"
payload="$(run payload --entry "$entry" --valid-until "$valid_until" --network testnet --json)"
python3 - "$payload" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
if len(doc.get("payload", "")) != 64:
    raise SystemExit(f"payload is not a 32-byte hex digest: {doc.get('payload')!r}")
PY

echo "== $platform: verify"
verify="$(run verify --entry "$signed" --network testnet)"
case "$verify" in
  *verified*) ;;
  *) fail "verify did not report a verified signature: $verify" ;;
esac

echo "== $platform: diff"
diff_output="$(run diff --before "$entry" --after "$entry")"
case "$diff_output" in
  *identical*) ;;
  *) fail "diff did not report identical entries: $diff_output" ;;
esac

echo "== $platform: delegates"
wrapped="$(run delegates --entry "$entry" --valid-until "$valid_until" --delegate "$delegate")"
[ -n "$wrapped" ] || fail "delegates printed nothing"

echo "== $platform: man and completions"
run man >/dev/null
run completions --shell bash >/dev/null

# The sign path is exercised without a usable seed: the command must start,
# reach the seed check, and refuse with the usage exit code rather than crash.
echo "== $platform: sign refuses without a seed"
set +e
run sign --entry "$entry" --valid-until "$valid_until" --network testnet --secret-env SOROAUTH_SMOKE_UNSET >/dev/null 2>&1
sign_status=$?
set -e
[ "$sign_status" -eq 2 ] || fail "sign without a seed exited $sign_status, want 2"

echo "smoke-image: $platform: all documented offline commands passed"

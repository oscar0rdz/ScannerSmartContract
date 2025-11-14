#!/usr/bin/env zsh
set -euo pipefail

# run_demo_single_candidate.sh
# Runs the scanner, saves outputs to disk, picks ONE candidate with strict red flags
# (uses_delegatecall_opcode + can_selfdestruct_opcode) and runs the deep audit for that
# candidate. Safe defaults suitable for a short demo.

TOKEN=${1:-usdt}
BLOCKS_BACK=${2:-50}
LIMIT=${3:-20}
MIN_VOLUME=${4:-100}

OUT_JSON="scanner_${TOKEN}.json"
OUT_LOGS="scanner_${TOKEN}.logs.txt"

PY=".venv/bin/python"
SCAN="token_transfer_scanner.py"
FILTER="filter_and_audit_from_scanner.py"

echo "[*] Demo (single candidate): token=${TOKEN} blocks_back=${BLOCKS_BACK} limit=${LIMIT} min_volume=${MIN_VOLUME}"

# Load .env if present
if [ -f .env ]; then
  echo "[*] Loading .env"
  # shellcheck disable=SC2046
  export $(grep -v '^#' .env | xargs -r)
fi

if [ ! -x "$PY" ]; then
  PY="$(command -v python || true)"
  if [ -z "$PY" ]; then
    echo "[ERROR] No python found. Activate your .venv or install Python." >&2
    exit 2
  fi
fi

echo "[*] Running scanner. JSON -> $OUT_JSON  | logs -> $OUT_LOGS"
"$PY" "$SCAN" --token "$TOKEN" --blocks-back "$BLOCKS_BACK" --limit "$LIMIT" > "$OUT_JSON" 2> "$OUT_LOGS" || {
  echo "[ERROR] Scanner failed. See $OUT_LOGS" >&2
  exit 3
}

if [ ! -s "$OUT_JSON" ]; then
  echo "[WARN] Scanner output ($OUT_JSON) is empty. Check $OUT_LOGS" >&2
  exit 0
fi

echo "[*] Running filter to pick a single red-flag candidate (min_volume=${MIN_VOLUME})"
"$PY" "$FILTER" "$OUT_JSON" --min-volume "$MIN_VOLUME" --max 1

if [ ! -f candidates_for_audit.json ]; then
  echo "[WARN] No candidates_for_audit.json produced. Nothing to audit." >&2
  exit 0
fi

ADDR=$($PY - <<'PY'
import json,sys
try:
  arr=json.load(open('candidates_for_audit.json', 'r'))
  if isinstance(arr, list) and arr:
    sys.stdout.write(arr[0].get('address',''))
except Exception:
  pass
PY
)
if [ -z "$ADDR" ]; then
  echo "[WARN] candidates_for_audit.json empty or malformed." >&2
  exit 0
fi

echo "[*] Selected candidate: $ADDR"
echo "[*] Running deep audit for $ADDR (no-mythril for speed)"
"$PY" contract_deep_audit.py --address "$ADDR" --no-mythril || {
  echo "[ERROR] contract_deep_audit.py failed for $ADDR" >&2
  exit 4
}

echo "[*] Audit finished. Check audit_output/$ADDR for results (source, abi, summary)."

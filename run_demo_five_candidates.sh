#!/usr/bin/env zsh
set -euo pipefail

# run_demo_five_candidates.sh
# Scans, saves JSON+logs, selects up to N candidates (default 5) and runs deep audit for each.
# Usage: ./run_demo_five_candidates.sh [token] [blocks_back] [limit] [min_volume] [max_candidates]

TOKEN=${1:-usdt}
BLOCKS_BACK=${2:-50}
LIMIT=${3:-50}
MIN_VOLUME=${4:-100}
MAX_CANDIDATES=${5:-5}

OUT_JSON="scanner_${TOKEN}.json"
OUT_LOGS="scanner_${TOKEN}.logs.txt"

PY=".venv/bin/python"
SCAN="token_transfer_scanner.py"
FILTER="filter_and_audit_from_scanner.py"

echo "[*] Demo (multi candidates): token=${TOKEN} blocks_back=${BLOCKS_BACK} limit=${LIMIT} min_volume=${MIN_VOLUME} max_candidates=${MAX_CANDIDATES}"

# Load .env if present
if [ -f .env ]; then
  echo "[*] Loading .env"
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

echo "[*] Running filter to pick up to $MAX_CANDIDATES candidates (min_volume=${MIN_VOLUME})"
"$PY" "$FILTER" "$OUT_JSON" --min-volume "$MIN_VOLUME" --max "$MAX_CANDIDATES"

if [ ! -f candidates_for_audit.json ]; then
  echo "[WARN] No candidates_for_audit.json produced. Nothing to audit." >&2
  exit 0
fi

echo "[*] Extracting addresses to audit"
ADDRS=$($PY - <<'PY'
import json,sys
try:
    arr=json.load(open('candidates_for_audit.json'))
    out=[x.get('address') for x in arr if x.get('address')]
    sys.stdout.write('\n'.join(out))
except Exception:
    pass
PY
)

if [ -z "$ADDRS" ]; then
  echo "[WARN] No addresses found in candidates_for_audit.json" >&2
  exit 0
fi

echo "[*] Auditing up to $MAX_CANDIDATES addresses"
count=0
echo "$ADDRS" | while read -r addr; do
  if [ -z "$addr" ]; then
    continue
  fi
  count=$((count+1))
  echo "\n===================================================="
  echo "[*] Running deep audit for $addr ($count/$MAX_CANDIDATES)"
  echo "====================================================\n"
  "$PY" contract_deep_audit.py --address "$addr" --no-mythril || echo "[WARN] Audit failed for $addr"
  if [ "$count" -ge "$MAX_CANDIDATES" ]; then
    break
  fi
done

echo "[*] All done. Audits saved under audit_output/"

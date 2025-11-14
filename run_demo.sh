#!/usr/bin/env zsh
set -euo pipefail

# run_demo.sh
# Usage: ./run_demo.sh [token] [blocks_back] [limit] [min_volume] [max_candidates]
# Example: ./run_demo.sh usdt 50 5 100 5

TOKEN=${1:-usdt}
BLOCKS_BACK=${2:-50}
LIMIT=${3:-5}
MIN_VOLUME=${4:-100}
MAX_CANDIDATES=${5:-5}

OUT_JSON="scanner_${TOKEN}.json"
OUT_LOGS="scanner_${TOKEN}.logs.txt"

PY=".venv/bin/python"
SCAN="token_transfer_scanner.py"
FILTER="filter_and_audit_from_scanner.py"

echo "[*] Demo runner: token=${TOKEN} blocks_back=${BLOCKS_BACK} limit=${LIMIT}"

# Load .env if present (simple export; ensure your .env has no complex quoting)
if [ -f .env ]; then
  echo "[*] Loading .env"
  # shellcheck disable=SC2046
  export $(grep -v '^#' .env | xargs -r)
fi

if [ ! -x "$PY" ]; then
  echo "[WARN] Python executable $PY not found or not executable. Attempting to use system python."
  PY="$(command -v python || true)"
  if [ -z "$PY" ]; then
    echo "[ERROR] No python found. Activate your .venv or adjust PY path in the script." >&2
    exit 2
  fi
fi

echo "[*] Running scanner -> output: $OUT_JSON, logs: $OUT_LOGS"
"$PY" "$SCAN" --token "$TOKEN" --blocks-back "$BLOCKS_BACK" --limit "$LIMIT" > "$OUT_JSON" 2> "$OUT_LOGS" || {
  echo "[ERROR] Scanner exited with non-zero status. See $OUT_LOGS" >&2
  exit 3
}

if [ ! -s "$OUT_JSON" ]; then
  echo "[WARN] Scanner produced empty JSON ($OUT_JSON). Check $OUT_LOGS for details." >&2
  exit 0
fi

echo "[*] Running filter + audit (min_volume=${MIN_VOLUME}, max=${MAX_CANDIDATES})"
"$PY" "$FILTER" "$OUT_JSON" --min-volume "$MIN_VOLUME" --max "$MAX_CANDIDATES"

echo "[*] Demo complete. Files produced:"
echo "  - JSON: $OUT_JSON"
echo "  - Logs: $OUT_LOGS"
echo "  - Candidates: candidates_for_audit.json"
echo "  - Audits dir: audit_output/"

echo "[*] Top candidates (if any):"
if [ -f candidates_for_audit.json ]; then
  jq -c '.[]' candidates_for_audit.json | sed -n '1,10p' || true
else
  echo "  (no candidates_for_audit.json)"
fi

echo "[*] Recent audit folders (head):"
ls -1 audit_output 2>/dev/null | head -n 10 || true

echo "[*] To record a video: run this script and then show the JSON, logs, and an audit folder's source/summary for a walkthrough."

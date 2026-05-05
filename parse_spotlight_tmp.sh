#!/bin/zsh
set -euo pipefail

# Parse tmp artifacts from scan_crypto_v5 and run spotlight_parser when available.
# Output is paged via `more`.

OUTDIR="${1:-$HOME/Documents/scan_crypto}"
CSV="$OUTDIR/results.csv"
REPORT="$OUTDIR/spotlight_parse_report.txt"

if [[ ! -d "$OUTDIR" ]]; then
  echo "Missing directory: $OUTDIR" >&2
  exit 1
fi

if [[ ! -f "$CSV" ]]; then
  echo "Missing results file: $CSV" >&2
  echo "Run scan_crypto_v5.sh first." >&2
  exit 1
fi

SPOTLIGHT_BIN=""
if command -v spotlight_parser >/dev/null 2>&1; then
  SPOTLIGHT_BIN="spotlight_parser"
elif command -v spotlight_parser.py >/dev/null 2>&1; then
  SPOTLIGHT_BIN="spotlight_parser.py"
elif [[ -f ./spotlight_parser.py ]]; then
  SPOTLIGHT_BIN="./spotlight_parser.py"
fi

build_reason() {
  local raw_high="$1"
  local raw_low="$2"
  local bip_valid="$3"
  local bip_candidate="$4"
  local fs_hits="$5"
  local ext_hits="$6"

  local reasons=()
  (( raw_high > 0 )) && reasons+=("high-confidence address/key patterns")
  (( bip_valid > 0 )) && reasons+=("valid BIP39 seed phrase checksum")
  (( fs_hits > 0 )) && reasons+=("filesystem content matches crypto indicators")
  (( ext_hits > 0 )) && reasons+=("interesting filenames (wallet/keystore/backup-like)")
  (( raw_low > 0 && raw_high == 0 )) && reasons+=("low-confidence keyword indicators")
  (( bip_candidate > 0 && bip_valid == 0 )) && reasons+=("candidate BIP39 phrases (needs validation)")

  if [[ ${#reasons[@]} -eq 0 ]]; then
    echo "No direct indicators; included for completeness"
  else
    local joined="${(j:, :)reasons}"
    echo "$joined"
  fi
}

run_spotlight_parse() {
  local part="$1"
  local outfile="$2"

  local candidates=(
    "$OUTDIR/${part}_all_hits_with_offsets.txt"
    "$OUTDIR/${part}_high.txt"
    "$OUTDIR/${part}_low.txt"
    "$OUTDIR/${part}_fs_hits.txt"
    "$OUTDIR/${part}_interesting_filenames.txt"
  )

  if [[ -z "$SPOTLIGHT_BIN" ]]; then
    {
      echo "spotlight_parser not found in PATH."
      echo "Install from: https://github.com/ydkhatri/spotlight_parser"
    } > "$outfile"
    return
  fi

  : > "$outfile"
  local f
  for f in "${candidates[@]}"; do
    [[ -s "$f" ]] || continue
    {
      echo "---- spotlight_parser on $(basename "$f") ----"
      "$SPOTLIGHT_BIN" "$f" 2>&1 || true
      echo
    } >> "$outfile"
  done

  if [[ ! -s "$outfile" ]]; then
    echo "No non-empty partition artifacts found for spotlight parsing." > "$outfile"
  fi
}

{
  echo "Spotlight Temp Parse Report"
  echo "Generated: $(date)"
  echo "Source tmp dir: $OUTDIR"
  echo
} > "$REPORT"

while IFS=, read -r parent partition raw_high raw_low bip_valid bip_candidate fs_hits ext_hits action; do
  [[ "$parent" == "parent" ]] && continue
  [[ "$partition" == "ALL" ]] && continue

  [[ "$partition" =~ ^disk[0-9]+s[0-9]+$ ]] || continue

  reason=$(build_reason "$raw_high" "$raw_low" "$bip_valid" "$bip_candidate" "$fs_hits" "$ext_hits")
  part_parse_out="$OUTDIR/${partition}_spotlight_parse.txt"
  run_spotlight_parse "$partition" "$part_parse_out"

  {
    echo "============================================================"
    echo "Drive: /dev/$parent"
    echo "Partition: /dev/$partition"
    echo "Relevance: $reason"
    echo "Metrics: raw_high=$raw_high raw_low=$raw_low bip39_valid=$bip_valid bip39_candidate=$bip_candidate fs_hits=$fs_hits ext_hits=$ext_hits action=$action"
    echo "spotlight_parser output: $part_parse_out"
    echo "------------------------------------------------------------"
    sed -n '1,120p' "$part_parse_out"
    echo
  } >> "$REPORT"
done < "$CSV"

cat "$REPORT" | more

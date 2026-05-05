#!/bin/zsh
# MIT License
#
# Copyright (c) 2026 DaveMathews.com
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# scan_crypto_v5.sh
# Read-only crypto forensic triage for USB drives and SD cards.
# No disk image copy.
# Single-file script.
#
# Run:
#   sudo zsh scan_crypto_v5.sh
#
# Optional helpers:
#   brew install pv foremost
#   python3 -m pip install mnemonic
#
# Output (default):
#   ~/Documents/crypto_scan/summary.txt
#   ~/Documents/crypto_scan/results.csv
#   ~/Documents/crypto_scan/run.log

set -uo pipefail
export LC_ALL=C
export LANG=C
SCRIPT_VERSION="v5.7.1"

SHOW_ALL_JPG=0
AUTO_EJECT_OVERRIDE=""
OUTDIR="$HOME/Documents/crypto_scan"
FORCE_DEEP_SCAN=0
FAST_MODE=0
MIN_FREE_GB=20

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all-jpg)
      SHOW_ALL_JPG=1
      shift
      ;;
    --no-auto-eject)
      AUTO_EJECT_OVERRIDE=0
      shift
      ;;
    --version)
      echo "scan_crypto_v5.sh ${SCRIPT_VERSION}"
      exit 0
      ;;
    --deep)
      FORCE_DEEP_SCAN=1
      shift
      ;;
    --fast)
      FAST_MODE=1
      shift
      ;;
    --outdir)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --outdir" >&2
        exit 1
      fi
      OUTDIR="$2"
      shift 2
      ;;
    --min-free-gb)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --min-free-gb" >&2
        exit 1
      fi
      MIN_FREE_GB="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: sudo zsh $0 [--all-jpg] [--fast] [--deep] [--no-auto-eject] [--outdir <path>] [--min-free-gb <N>] [--version]" >&2
      exit 1
      ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Must run as root: sudo zsh $0" >&2
  exit 1
fi

mkdir -p "$OUTDIR"

SUMMARY="$OUTDIR/summary.txt"
CSV="$OUTDIR/results.csv"
LOG="$OUTDIR/run.log"

bytes_free_for_path() {
  local path="$1"
  df -k "$path" 2>/dev/null | /usr/bin/awk 'NR==2 {print $4 * 1024}'
}

ensure_min_free_or_exit() {
  local path="$1"
  local phase="$2"
  local free_bytes
  local min_bytes

  free_bytes=$(bytes_free_for_path "$path")
  min_bytes=$(( MIN_FREE_GB * 1024 * 1024 * 1024 ))

  if [[ -z "$free_bytes" ]]; then
    echo "Could not determine free space for $path during $phase." | /usr/bin/tee -a "$SUMMARY"
    exit 1
  fi

  if (( free_bytes < min_bytes )); then
    echo "ABORT: low disk space during $phase. Free=${free_bytes} bytes, required minimum=${min_bytes} bytes (${MIN_FREE_GB} GiB)." | /usr/bin/tee -a "$SUMMARY"
    echo "Use --outdir to another volume or lower reserve with --min-free-gb." | /usr/bin/tee -a "$SUMMARY"
    exit 1
  fi
}

: > "$SUMMARY"
: > "$LOG"

echo "parent,partition,raw_high,raw_low,bip39_valid,bip39_candidate,fs_hits,ext_hits,action" > "$CSV"

printf "Scan started: %s\n" "$(/usr/bin/date)" | /usr/bin/tee -a "$SUMMARY"
printf "Script version: %s\n" "$SCRIPT_VERSION" | /usr/bin/tee -a "$SUMMARY"
printf "Output directory: %s\n\n" "$OUTDIR" | /usr/bin/tee -a "$SUMMARY"
printf "Storage safety reserve: %s GiB free minimum\n\n" "$MIN_FREE_GB" | /usr/bin/tee -a "$SUMMARY"
printf "Tip: use --outdir to store results elsewhere.\n\n" | /usr/bin/tee -a "$SUMMARY"
printf "Searching for: wallet files, crypto address/key patterns, BIP39 seed phrases, and interesting filenames (including JPG/JPEG).\n\n" | /usr/bin/tee -a "$SUMMARY"
printf "Status: initializing device discovery...\n\n" | /usr/bin/tee -a "$SUMMARY"
if [[ "$FAST_MODE" -eq 1 ]]; then
  printf "Scan profile: FAST mode (raw-only triage + optional carving). Mounted filesystem and extension scans are skipped.\n\n" | /usr/bin/tee -a "$SUMMARY"
else
  printf "Scan profile: speed-first (raw triage first; fs/ext scans run only when raw indicators exist). Use --deep to force full mounted-filesystem scanning.\n\n" | /usr/bin/tee -a "$SUMMARY"
fi

ensure_min_free_or_exit "$OUTDIR" "startup"

BS=64m
MIN_STR=6

AUTO_EJECT_NO_HITS=0
RUN_FOREMOST_ON_STRONG_HITS=1
RUN_FS_SCAN=1
RUN_EXT_SCAN=1
[[ -n "$AUTO_EJECT_OVERRIDE" ]] && AUTO_EJECT_NO_HITS="$AUTO_EJECT_OVERRIDE"

PAT_HIGH=(
  'bc1[a-zA-HJ-NP-Z0-9]{25,90}'
  '[13][a-km-zA-HJ-NP-Z1-9]{25,34}'
  '0x[0-9a-fA-F]{40}'
  '4[1-9A-HJ-NP-Za-km-z]{94}'
  'T[1-9A-HJ-NP-Za-km-z]{33}'
  '5[1-9A-HJ-NP-Za-km-z]{50}'
  '[KL][1-9A-HJ-NP-Za-km-z]{51}'
  'xprv[1-9A-HJ-NP-Za-km-z]{100,115}'
  'xpub[1-9A-HJ-NP-Za-km-z]{100,115}'
  '[yz]prv[1-9A-HJ-NP-Za-km-z]{100,115}'
  '[yz]pub[1-9A-HJ-NP-Za-km-z]{100,115}'
  '"ciphertext"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]{64,}"'
  '"crypto"[[:space:]]*:'
  '"kdf"[[:space:]]*:'
)

PAT_LOW=(
  'wallet\.dat'
  'wallet'
  'keystore'
  'mnemonic'
  'seed[ _.-]?phrase'
  'recovery[ _.-]?phrase'
  'restore[ _.-]?phrase'
  'restoration[ _.-]?phrase'
  'private[ _.-]?key'
  'secret[ _.-]?key'
  'UTC--[0-9]'
  'bitcoin'
  'ethereum'
  'solana'
  'monero'
  'litecoin'
  'dogecoin'
  'metamask'
  'ledger'
  'trezor'
  'electrum'
  'exodus'
  'phantom'
  'coinbase'
  'trust[ _.-]?wallet'
)

RE_HIGH="${(j:|:)PAT_HIGH}"
RE_LOW="${(j:|:)PAT_LOW}"
RE_ALL="${RE_HIGH}|${RE_LOW}"
RE_FS_EXTRA='[0-9a-fA-F]{64}'
RE_JPG_NAME='(wallet|seed|mnemonic|recovery|restore|backup|private[ _.-]?key|secret|passphrase|keystore|metamask|ledger|trezor|electrum|exodus|phantom|coinbase|trust[ _.-]?wallet|crypto|bitcoin|ethereum|solana|doge|litecoin|monero)'

INTERESTING_EXTS=(
  'wallet.dat'
  '*.wallet'
  '*.keystore'
  '*.key'
  '*.seed'
  'UTC--*'
  '*.aes.json'
  '*.txt'
  '*.md'
  '*.rtf'
  '*.csv'
  '*.json'
  '*.bak'
  '*.old'
  '*.note'
  '*.text'
  '*.pdf'
  '*.png'
  '*.zip'
)

FM_CONF="$OUTDIR/foremost.conf"
cat > "$FM_CONF" <<'FMEOF'
jpg  y 200000000 \xff\xd8\xff      \xff\xd9
png  y 200000000 \x89\x50\x4e\x47 \x49\x45\x4e\x44
pdf  y 200000000 %PDF-             %%EOF
zip  y  50000000 PK\x03\x04
FMEOF

parent_of() {
  sed -E 's/s[0-9]+$//' <<< "$1"
}

probe_read() {
  dd if="$1" bs=512 count=1 of=/dev/null 2>/dev/null
}

partition_size_bytes() {
  local part="$1"
  /usr/sbin/diskutil info "/dev/$part" 2>/dev/null \
    | /usr/bin/awk '
      /Disk Size:/ {
        for (i=1; i<=NF; i++) {
          if ($i ~ /^\([0-9,]+$/ || $i ~ /^[0-9,]+$/) {
            gsub(/[^0-9]/, "", $i)
            if ($i != "") { print $i; exit }
          }
        }
      }'
}

is_system_or_container_partition() {
  local info="$1"
  local name type content mount

  name=$(echo "$info" | /usr/bin/awk -F: '/Volume Name:/ {$1=""; sub(/^[ \t]+/,""); print}')
  type=$(echo "$info" | /usr/bin/awk -F: '/Type \(Bundle\):/ {$1=""; sub(/^[ \t]+/,""); print}')
  content=$(echo "$info" | /usr/bin/awk -F: '/Partition Type:/ {$1=""; sub(/^[ \t]+/,""); print}')
  mount=$(echo "$info" | /usr/bin/awk -F: '/Mount Point:/ {$1=""; sub(/^[ \t]+/,""); print}')

  case "${name:l}" in
    efi|preboot|recovery|vm|update|xarts|hardware) return 0 ;;
  esac

  case "${type:l}" in
    *efi*|*apfs*) return 0 ;;
  esac

  case "${content:l}" in
    *efi*|*apple_partition_map*|*apple_partition_scheme*|*guid_partition_scheme*|*fdisk_partition_scheme*) return 0 ;;
  esac

  case "$mount" in
    /System*|/private/var/vm*|/Volumes/Preboot*|/Volumes/Recovery*|/Volumes/VM*) return 0 ;;
  esac

  return 1
}

discover_target_partitions() {
  local -a parents partitions

  for disk in ${(f)"$(/usr/sbin/diskutil list | /usr/bin/awk '/^\/dev\/disk[0-9]+/ {gsub("/dev/", "", $1); print $1}')"}; do
    local info internal removable ejectable virtual protocol device_location

    info=$(/usr/sbin/diskutil info "/dev/$disk" 2>/dev/null)
    [[ -z "$info" ]] && continue

    internal=$(echo "$info" | /usr/bin/awk -F: '/Internal:/ {gsub(/^[ \t]+/,"",$2); print $2}')
    removable=$(echo "$info" | /usr/bin/awk -F: '/Removable Media:/ {gsub(/^[ \t]+/,"",$2); print $2}')
    ejectable=$(echo "$info" | /usr/bin/awk -F: '/Ejectable:/ {gsub(/^[ \t]+/,"",$2); print $2}')
    virtual=$(echo "$info" | /usr/bin/awk -F: '/Virtual:/ {gsub(/^[ \t]+/,"",$2); print $2}')
    protocol=$(echo "$info" | /usr/bin/awk -F: '/Protocol:/ {gsub(/^[ \t]+/,"",$2); print $2}')
    device_location=$(echo "$info" | /usr/bin/awk -F: '/Device Location:/ {gsub(/^[ \t]+/,"",$2); print $2}')

    # Hard skips: internal Mac storage, APFS synthesized containers, disk images.
    [[ "$internal" == "Yes" ]] && continue
    [[ "$virtual" == "Yes" ]] && continue

    # Broadly allow USB / SD / ejectable / removable / external devices.
    if [[ "$removable" == "Yes" || \
          "$ejectable" == "Yes" || \
          "$protocol" == "USB" || \
          "$protocol" == "Secure Digital" || \
          "$protocol" == "SD" || \
          "$device_location" == "External" ]]; then
      parents+=("$disk")
    fi
  done

  parents=("${(@u)parents}")

  for parent in "${parents[@]}"; do
    while IFS= read -r part; do
      [[ -z "$part" ]] && continue
      [[ ! "$part" =~ ^${parent}s[0-9]+$ ]] && continue

      local pinfo
      pinfo=$(/usr/sbin/diskutil info "/dev/$part" 2>/dev/null)
      [[ -z "$pinfo" ]] && continue

      if is_system_or_container_partition "$pinfo"; then
        printf "Skipping system/container partition: %s\n" "$part" >> "$LOG"
        continue
      fi

      partitions+=("$part")
    done < <(/usr/sbin/diskutil list "/dev/$parent" 2>/dev/null | /usr/bin/awk '/disk[0-9]+s[0-9]+$/ {print $NF}')
  done

  print -l "${(@u)partitions}"
}

raw_stream_with_progress() {
  local src="$1"
  local size="$2"
  local label="$3"

  if command -v pv >/dev/null 2>&1 && [[ -n "$size" && "$size" -gt 0 ]]; then
    dd if="$src" bs="$BS" iflag=fullblock 2>>"$LOG" | pv -f -s "$size" -N "$label"
  elif command -v pv >/dev/null 2>&1; then
    dd if="$src" bs="$BS" iflag=fullblock 2>>"$LOG" | pv -f -N "$label"
  else
    echo "  pv not installed, using dd status=progress" > /dev/tty
    dd if="$src" bs="$BS" iflag=fullblock status=progress 2>>"$LOG"
  fi
}

best_bs_for_source() {
  local src="$1"
  local test_file="$OUTDIR/.bs_probe.$$"
  local bs
  for bs in 64m 32m 16m; do
    if dd if="$src" bs="$bs" count=1 of="$test_file" iflag=fullblock 2>>"$LOG"; then
      rm -f "$test_file"
      echo "$bs"
      return
    fi
  done
  rm -f "$test_file"
  echo "16m"
}

phase_progress() {
  local label="$1"
  local step="$2"
  local total="$3"
  local width=24
  local filled=$(( width * step / total ))
  local empty=$(( width - filled ))
  local bar="${(r:$filled::#:):-}${(r:$empty::-:):-}"
  printf "  [%s] [%s] %d/%d\n" "$label" "$bar" "$step" "$total" | /usr/bin/tee -a "$SUMMARY"
}

bip39_stream_scan() {
  local valid_file="$1"
  local cand_file="$2"

  python3 - "$valid_file" "$cand_file" <<'PY'
import sys, re

valid_file = sys.argv[1]
cand_file = sys.argv[2]
phrase_lengths = (12, 15, 18, 21, 24)
token_re = re.compile(r"[a-zA-Z]{3,8}")

try:
    from mnemonic import Mnemonic
    mnemo = Mnemonic("english")
    wordset = set(mnemo.wordlist)
except Exception:
    open(valid_file, "w").close()
    open(cand_file, "w").close()
    sys.exit(0)

valid_hits = set()
candidate_hits = set()
buf = []

def check_buffer():
    global buf
    if len(buf) > 80:
        buf = buf[-80:]
    n = len(buf)
    for start in range(max(0, n - 80), n):
        for length in phrase_lengths:
            end = start + length
            if end > n:
                continue
            seq = buf[start:end]
            if all(w in wordset for w in seq):
                phrase = " ".join(seq)
                candidate_hits.add(phrase)
                try:
                    if mnemo.check(phrase):
                        valid_hits.add(phrase)
                except Exception:
                    pass

for line in sys.stdin:
    toks = [t.lower() for t in token_re.findall(line)]
    if not toks:
        continue
    for t in toks:
        if t in wordset:
            buf.append(t)
        else:
            if len(buf) >= 12:
                check_buffer()
            buf = []
    if len(buf) >= 12:
        check_buffer()

check_buffer()

with open(valid_file, "w") as vf:
    for h in sorted(valid_hits):
        vf.write(h + "\n")

with open(cand_file, "w") as cf:
    for h in sorted(candidate_hits):
        if h not in valid_hits:
            cf.write(h + "\n")
PY
}

fs_scan() {
  local mount="$1"
  local out_file="$2"
  local label="$3"
  local BAR_WIDTH=40
  local fs_hits=0

  : > "$out_file"

  local -a files
  files=("${(@f)$(find "$mount" -type f 2>/dev/null)}")
  local total="${#files[@]}"

  if [[ "$total" -eq 0 ]]; then
    printf "  [fs] %s: no files\n" "$label" > /dev/tty
    echo 0
    return
  fi

  local current=0
  local fs_start_ts
  fs_start_ts=$(/usr/bin/date +%s)
  for f in "${files[@]}"; do
    (( current++ ))
    local filled=$(( BAR_WIDTH * current / total ))
    local empty=$(( BAR_WIDTH - filled ))
    local bar="${(r:$filled::#:):-}${(r:$empty::-:):-}"
    local now elapsed rate remaining eta
    now=$(/usr/bin/date +%s)
    elapsed=$(( now - fs_start_ts ))
    (( elapsed < 1 )) && elapsed=1
    rate=$(( current / elapsed ))
    (( rate < 1 )) && rate=1
    remaining=$(( (total - current) / rate ))
    eta=$(( now + remaining ))
    printf "\r  [fs] %s [%s] %d/%d files | eta ~ %s " \
      "$label" "$bar" "$current" "$total" "$(/usr/bin/date -r "$eta" +%H:%M:%S)" > /dev/tty

    local reason=""
    if LC_ALL=C grep -qiE "$RE_ALL" "$f" 2>/dev/null; then
      reason="fs-crypto"
    elif LC_ALL=C grep -qE "$RE_FS_EXTRA" "$f" 2>/dev/null; then
      reason="fs-hex64"
    fi

    if [[ -n "$reason" ]]; then
      (( fs_hits++ ))
      printf "\n  \$\$ [%s] %s\n" "$reason" "$f" > /dev/tty
      printf "%s\t%s\n" "$reason" "$f" >> "$out_file"
      LC_ALL=C grep -iE "$RE_HIGH|$RE_FS_EXTRA" "$f" 2>/dev/null \
        | /usr/bin/head -3 \
        | while IFS= read -r line; do
            printf "     -> %s\n" "${line:0:120}" > /dev/tty
          done
    fi
  done

  printf "\n  [fs] %s: %d scanned, %d hit(s)\n" "$label" "$total" "$fs_hits" > /dev/tty
  echo "$fs_hits"
}

ext_scan() {
  local mount="$1"
  local out_file="$2"

  : > "$out_file"

  for pat in "${INTERESTING_EXTS[@]}"; do
    find "$mount" -iname "$pat" 2>/dev/null >> "$out_file" || true
  done

  LC_ALL=C sort -u -o "$out_file" "$out_file" 2>/dev/null || true
  wc -l < "$out_file" | tr -d ' '
}

interesting_jpg_scan() {
  local mount="$1"
  local out_file="$2"

  : > "$out_file"
  find "$mount" -type f \( -iname '*.jpg' -o -iname '*.jpeg' \) -print 2>/dev/null \
    | /usr/bin/awk -F/ '{print $NF "\t" $0}' \
    | LC_ALL=C grep -iE "$RE_JPG_NAME" \
    | /usr/bin/awk -F'\t' '{print $2}' \
    >> "$out_file" || true
  LC_ALL=C sort -u -o "$out_file" "$out_file" 2>/dev/null || true
  wc -l < "$out_file" | tr -d ' '
}

preview_targets() {
  local -a disks
  disks=("$@")

  echo "Targets:" | /usr/bin/tee -a "$SUMMARY"
  for part in "${disks[@]}"; do
    echo "--- /dev/$part ---" | /usr/bin/tee -a "$SUMMARY"
    /usr/sbin/diskutil info "/dev/$part" 2>/dev/null \
      | /usr/bin/awk -F: '
          /Device Identifier/ ||
          /Device Node/ ||
          /Volume Name/ ||
          /Mounted/ ||
          /Mount Point/ ||
          /File System Personality/ ||
          /Protocol/ ||
          /Disk Size/ ||
          /Device Location/ {
            print "  "$0
          }' | /usr/bin/tee -a "$SUMMARY"
    echo "" | /usr/bin/tee -a "$SUMMARY"
  done
}

scan_partition() {
  local part="$1"
  local parent
  parent=$(parent_of "$part")

  local RAW="/dev/r${part}"
  local BLK="/dev/${part}"

  local ALL_HITS="$OUTDIR/${part}_all_hits_with_offsets.txt"
  local HIGH_TXT="$OUTDIR/${part}_high.txt"
  local LOW_TXT="$OUTDIR/${part}_low.txt"
  local VALID_BIP="$OUTDIR/${part}_bip39_valid.txt"
  local CAND_BIP="$OUTDIR/${part}_bip39_candidates.txt"
  local FS_TXT="$OUTDIR/${part}_fs_hits.txt"
  local EXT_TXT="$OUTDIR/${part}_interesting_filenames.txt"
  local JPG_TXT="$OUTDIR/${part}_interesting_jpg_files.txt"

  local raw_high=0 raw_low=0 bip_valid=0 bip_candidate=0 fs_count=0 ext_count=0

  local phase_total=4
  local part_start_ts
  part_start_ts=$(/usr/bin/date +%s)
  printf "=== %s ===\n" "$part" | /usr/bin/tee -a "$SUMMARY"
  phase_progress "scan" 0 "$phase_total"

  local SRC=""
  if probe_read "$RAW"; then
    SRC="$RAW"
  elif probe_read "$BLK"; then
    SRC="$BLK"
  fi

  : > "$ALL_HITS"
  : > "$HIGH_TXT"
  : > "$LOW_TXT"
  : > "$VALID_BIP"
  : > "$CAND_BIP"
  : > "$FS_TXT"
  : > "$EXT_TXT"
  : > "$JPG_TXT"

  if [[ -n "$SRC" ]]; then
    ensure_min_free_or_exit "$OUTDIR" "pre-raw-scan"
    phase_progress "raw" 1 "$phase_total"
    local size
    size=$(partition_size_bytes "$part")
    [[ -z "$size" ]] && size=0

    local best_bs
    best_bs=$(best_bs_for_source "$SRC")
    BS="$best_bs"
    printf "  [raw] %s, bs=%s, size=%s bytes\n" "$SRC" "$BS" "$size" | /usr/bin/tee -a "$SUMMARY"

    local RAW_TMP="$OUTDIR/${part}_raw_strings.tmp"
    ensure_min_free_or_exit "$OUTDIR" "pre-raw-temp-create"
    : > "$RAW_TMP"

    # One raw stream pass. Store temporary strings for BIP39 and regex split.
    # This avoids re-reading the physical device while keeping no disk image.
    raw_stream_with_progress "$SRC" "$size" "$part" \
      | strings -a -n "$MIN_STR" -t x 2>>"$LOG" \
      > "$RAW_TMP"

    LC_ALL=C grep -a -iE "$RE_ALL" "$RAW_TMP" | LC_ALL=C sort -u > "$ALL_HITS" || true

    LC_ALL=C grep -a -iE "$RE_HIGH" "$ALL_HITS" \
      | LC_ALL=C cut -d' ' -f2- \
      | LC_ALL=C sort -u > "$HIGH_TXT" || true

    LC_ALL=C grep -a -iE "$RE_LOW" "$ALL_HITS" \
      | LC_ALL=C cut -d' ' -f2- \
      | LC_ALL=C sort -u > "$LOW_TXT" || true

    LC_ALL=C cut -d' ' -f2- "$RAW_TMP" \
      | bip39_stream_scan "$VALID_BIP" "$CAND_BIP"

    rm -f "$RAW_TMP"

    raw_high=$(wc -l < "$HIGH_TXT" | tr -d ' ')
    raw_low=$(wc -l < "$LOW_TXT" | tr -d ' ')
    bip_valid=$(wc -l < "$VALID_BIP" | tr -d ' ')
    bip_candidate=$(wc -l < "$CAND_BIP" | tr -d ' ')

    printf "\n  [raw] HIGH=%s LOW=%s BIP39_valid=%s BIP39_candidate=%s\n" \
      "$raw_high" "$raw_low" "$bip_valid" "$bip_candidate" | /usr/bin/tee -a "$SUMMARY"

    if [[ "$raw_high" -gt 0 ]]; then
      echo "  [raw] HIGH first 60:" | /usr/bin/tee -a "$SUMMARY"
      head -60 "$HIGH_TXT" | /usr/bin/sed 's/^/    /' | /usr/bin/tee -a "$SUMMARY"
      echo "  [raw] detailed hit offsets and matched lines saved to: $ALL_HITS" | /usr/bin/tee -a "$SUMMARY"
    fi

    if [[ "$raw_low" -gt 0 ]]; then
      echo "  [raw] LOW first 25:" | /usr/bin/tee -a "$SUMMARY"
      head -25 "$LOW_TXT" | /usr/bin/sed 's/^/    /' | /usr/bin/tee -a "$SUMMARY"
    fi

    if [[ "$bip_valid" -gt 0 ]]; then
      echo "  [bip39] VALID checksum phrases:" | /usr/bin/tee -a "$SUMMARY"
      head -40 "$VALID_BIP" | /usr/bin/sed 's/^/    /' | /usr/bin/tee -a "$SUMMARY"
    fi

    if [[ "$bip_candidate" -gt 0 ]]; then
      echo "  [bip39] candidate phrases, checksum not valid:" | /usr/bin/tee -a "$SUMMARY"
      head -40 "$CAND_BIP" | /usr/bin/sed 's/^/    /' | /usr/bin/tee -a "$SUMMARY"
    fi
  else
    printf "  [raw] skipped, no read access. Add Terminal to Full Disk Access.\n" | /usr/bin/tee -a "$SUMMARY"
  fi

  local mount_point=""
  mount_point=$(/usr/sbin/diskutil info "/dev/$part" 2>/dev/null \
    | /usr/bin/awk '/Mount Point:/ {$1=$2=""; sub(/^[[:space:]]+/,""); print}') || true

  local raw_signal_total=$(( raw_high + raw_low + bip_valid + bip_candidate ))
  local run_deep_for_part=0
  if [[ "$FORCE_DEEP_SCAN" -eq 1 || "$raw_signal_total" -gt 0 ]]; then
    run_deep_for_part=1
  fi

  if [[ "$FAST_MODE" -eq 1 ]]; then
    printf "  [fs] skipped in --fast mode (raw triage only; no mounted-file content walk)\n" | /usr/bin/tee -a "$SUMMARY"
  elif [[ "$RUN_FS_SCAN" -eq 1 && "$run_deep_for_part" -eq 1 && -n "$mount_point" && -d "$mount_point" ]]; then
    phase_progress "fs" 2 "$phase_total"
    printf "  [fs] %s\n" "$mount_point" | /usr/bin/tee -a "$SUMMARY"
    fs_count=$(fs_scan "$mount_point" "$FS_TXT" "$part")

    if [[ "$fs_count" -gt 0 ]]; then
      echo "  [fs] matching files:" | /usr/bin/tee -a "$SUMMARY"
      sed 's/^/    /' "$FS_TXT" | /usr/bin/tee -a "$SUMMARY"
    fi

    if [[ "$RUN_EXT_SCAN" -eq 1 ]]; then
      phase_progress "ext" 3 "$phase_total"
      ext_count=$(ext_scan "$mount_point" "$EXT_TXT")
      if [[ "$ext_count" -gt 0 ]]; then
        echo "  [fs] interesting filenames: $ext_count" | /usr/bin/tee -a "$SUMMARY"
        head -80 "$EXT_TXT" | /usr/bin/sed 's/^/    /' | /usr/bin/tee -a "$SUMMARY"
      fi
    fi

    if [[ "$SHOW_ALL_JPG" -eq 1 ]]; then
      local jpg_count=0
      jpg_count=$(interesting_jpg_scan "$mount_point" "$JPG_TXT")
      echo "  [jpg] interesting JPG/JPEG filenames: $jpg_count" | /usr/bin/tee -a "$SUMMARY"
      if [[ "$jpg_count" -gt 0 ]]; then
        head -120 "$JPG_TXT" | /usr/bin/sed 's/^/    /' | /usr/bin/tee -a "$SUMMARY"
      fi
    fi
  else
    if [[ "$run_deep_for_part" -eq 0 ]]; then
      printf "  [fs] skipped (no raw indicators; speed-first mode)\n" | /usr/bin/tee -a "$SUMMARY"
    else
      printf "  [fs] not mounted or disabled\n" | /usr/bin/tee -a "$SUMMARY"
    fi
  fi

  local strong_total=$(( raw_high + bip_valid ))
  if [[ "$RUN_FOREMOST_ON_STRONG_HITS" -eq 1 && "$strong_total" -gt 0 && -n "$SRC" ]] \
      && command -v foremost >/dev/null 2>&1; then
    ensure_min_free_or_exit "$OUTDIR" "pre-foremost-carving"
    phase_progress "carve" 4 "$phase_total"
    printf "  [foremost] strong raw indicators found on %s; running targeted file carving to recover embedded artifacts\n" "$part" | /usr/bin/tee -a "$SUMMARY"

    local FMOUT="$OUTDIR/foremost_${part}"
    rm -rf "$FMOUT"

    foremost -c "$FM_CONF" -T -Q -i "$SRC" -o "$FMOUT" 2>>"$LOG" || true

    if [[ -f "$FMOUT/audit.txt" ]]; then
      /usr/bin/grep -v "^$" "$FMOUT/audit.txt" | /usr/bin/tail -40 | /usr/bin/tee -a "$SUMMARY"
    fi
  fi

  local total=$(( raw_high + raw_low + bip_valid + bip_candidate + fs_count + ext_count ))

  if [[ "$total" -gt 0 ]]; then
    PARENT_HAS_HITS[$parent]=1
    echo "$parent,$part,$raw_high,$raw_low,$bip_valid,$bip_candidate,$fs_count,$ext_count,keep" >> "$CSV"
  else
    echo "$parent,$part,0,0,0,0,0,0,no_hits" >> "$CSV"
    printf "  No crypto hits.\n" | /usr/bin/tee -a "$SUMMARY"
  fi

  local part_end_ts part_elapsed
  part_end_ts=$(/usr/bin/date +%s)
  part_elapsed=$(( part_end_ts - part_start_ts ))
  printf "  [time] partition %s elapsed: %ss\n\n" "$part" "$part_elapsed" | /usr/bin/tee -a "$SUMMARY"
}

# ── Main ─────────────────────────────────────────────────────────────────────
DISKS=("${(@f)$(discover_target_partitions)}")
# Defensive sanitize: only keep disk identifiers like disk10s1.
DISKS=("${(@f)$(printf '%s\n' "${DISKS[@]}" | LC_ALL=C grep -E '^disk[0-9]+s[0-9]+$' || true)}")

if [[ ${#DISKS[@]} -eq 0 ]]; then
  echo "No USB drives or SD-card-style external partitions found." | /usr/bin/tee -a "$SUMMARY"
  echo "Check: /usr/sbin/diskutil list" | /usr/bin/tee -a "$SUMMARY"
  exit 1
fi

printf "Partitions selected: %s\n\n" "${DISKS[*]}" | /usr/bin/tee -a "$SUMMARY"
printf "Status: %d partition(s) queued for scan.\n\n" "${#DISKS[@]}" | /usr/bin/tee -a "$SUMMARY"
preview_targets "${DISKS[@]}"

typeset -A PARENT_HAS_HITS
typeset -A PARENT_PARTS

for part in "${DISKS[@]}"; do
  parent=$(parent_of "$part")
  PARENT_PARTS[$parent]+=" $part"
  PARENT_HAS_HITS[$parent]=0
done

# Serial is deliberate. Parallel scans usually saturate shared USB/SD buses and get slower.
for part in "${DISKS[@]}"; do
  printf "Status: scanning /dev/%s\n" "$part" | /usr/bin/tee -a "$SUMMARY"
  scan_partition "$part"
done

printf "=== Eject decision ===\n" | /usr/bin/tee -a "$SUMMARY"

for parent in ${(k)PARENT_PARTS}; do
  if [[ "${PARENT_HAS_HITS[$parent]}" -eq 1 ]]; then
    printf "  KEEP  /dev/%s, hits found on:%s\n" "$parent" "${PARENT_PARTS[$parent]}" | /usr/bin/tee -a "$SUMMARY"
    echo "$parent,ALL,-,-,-,-,-,-,kept_hits" >> "$CSV"
  else
    printf "  CLEAN /dev/%s, no hits on:%s\n" "$parent" "${PARENT_PARTS[$parent]}" | /usr/bin/tee -a "$SUMMARY"

    if [[ "$AUTO_EJECT_NO_HITS" -eq 1 ]]; then
      /usr/sbin/diskutil eject "/dev/$parent" 2>&1 | /usr/bin/tee -a "$SUMMARY" || true
      echo "$parent,ALL,0,0,0,0,0,0,ejected" >> "$CSV"
    else
      printf "    auto-eject disabled\n" | /usr/bin/tee -a "$SUMMARY"
      echo "$parent,ALL,0,0,0,0,0,0,kept_clean" >> "$CSV"
    fi
  fi
done

printf "\nScan finished: %s\n" "$(/usr/bin/date)" | /usr/bin/tee -a "$SUMMARY"

printf "\nOutput:\n"
printf "  Summary: %s\n" "$SUMMARY"
printf "  CSV:     %s\n" "$CSV"
printf "  Log:     %s\n" "$LOG"
printf "  High:    %s/*_high.txt\n" "$OUTDIR"
printf "  Low:     %s/*_low.txt\n" "$OUTDIR"
printf "  BIP39:   %s/*_bip39_valid.txt and *_bip39_candidates.txt\n" "$OUTDIR"
printf "  Offsets: %s/*_all_hits_with_offsets.txt\n\n" "$OUTDIR"

# scan_cyrpto

Current script version: `v5.9.0`

`scan_crypto_v5.sh` is a powerful read-only crypto forensic triage utility for macOS.

It is built to quickly scan removable media for crypto-related evidence at scale, including:
- wallet and keystore indicators
- high-signal crypto address and key patterns
- BIP39 seed phrase candidates and valid checksums
- interesting filenames and targeted JPEG/JPEG filename indicators

## Why This Utility Is Powerful

- Scans as many removable USB, thumb, and SD-style drives as you can plug into your system.
- Automatically discovers eligible external partitions while skipping internal/system containers.
- Performs a raw strings pass plus mounted filesystem triage for broad evidence coverage.
- Includes a dedicated `--fast` mode for raw-only triage when speed is the priority.
- Uses a confidence-oriented workflow to help surface high-priority partitions for review.

## Smart Keep-or-Eject Workflow

The script evaluates each detected removable parent disk after scanning its partitions:
- Drives with meaningful hits are kept attached so you can investigate them.
- Drives with no significant findings can be ejected to reduce clutter and speed up triage workflows.

This lets you rapidly focus attention on the media most likely to contain relevant data while safely clearing out low-value devices.

## Usage

```bash
sudo zsh scan_crypto_v5.sh
```

Python requirement:
- Python 3 (`python3`) is required.
- Optional but recommended BIP39 validation dependency:

```bash
python3 -m pip install mnemonic
```

Optional modes:

```bash
sudo zsh scan_crypto_v5.sh --all-jpg
sudo zsh scan_crypto_v5.sh --fast
sudo zsh scan_crypto_v5.sh --deep
sudo zsh scan_crypto_v5.sh --no-auto-eject
sudo zsh scan_crypto_v5.sh --outdir ~/Documents/crypto_scan
sudo zsh scan_crypto_v5.sh --min-free-gb 30
sudo zsh scan_crypto_v5.sh --version
```

## Outputs

By default, output is written to:
- `~/Documents/crypto_scan/run_YYYYMMDD_HHMMSS/summary.txt`
- `~/Documents/crypto_scan/run_YYYYMMDD_HHMMSS/results.csv`
- `~/Documents/crypto_scan/run_YYYYMMDD_HHMMSS/run.log`

Plus per-partition hit artifacts for deeper review.

## Read/Write Safety (macOS)

- Target media (USB/SD) is read-only for this workflow.
- The scanner reads from device nodes such as `/dev/disk*` or `/dev/rdisk*` and mounted target volumes.
- The scanner does not write files to target media mount points such as `/Volumes/<target>`.
- `parse_spotlight_tmp.sh` reads scan artifacts and runs parser logic on those artifacts only.
- All generated files are written only to your configured `--outdir` (default: `~/Documents/crypto_scan`) on system storage.

Notes about macOS paths:
- `/dev/*` entries are device nodes, not normal output file locations.
- Writing to `~/Documents/...` writes to the internal system APFS data volume.

## License

MIT

Another DaveMathews.com creation - good luck finding your missing files on those old USB/Thumb/SD drives!

## Parse tmp artifacts with spotlight_parser

After a scan completes, run:

```bash
zsh parse_spotlight_tmp.sh
```

Optional custom output dir:

```bash
zsh parse_spotlight_tmp.sh ~/Documents/crypto_scan
```

What it does:
- reads `~/Documents/crypto_scan/results.csv`
- maps each partition back to its parent drive
- explains why each drive is relevant (high-confidence hits, BIP39, fs hits, etc.)
- runs `spotlight_parser` against per-partition artifacts when installed
- pages the final report using `| more`

If `spotlight_parser` is not found in `PATH`, it still builds the report and notes install instructions:
- https://github.com/ydkhatri/spotlight_parser

## Storage Safety

The scanner now enforces a free-space reserve to avoid filling your system disk:
- default reserve is `20 GiB`
- customize with `--min-free-gb <N>`
- scan aborts safely before heavy phases if free space drops below reserve

Example:

```bash
sudo zsh scan_crypto_v5.sh --min-free-gb 30
```

## Fast Mode

Use `--fast` for the quickest triage path:
- runs raw scan + pattern extraction + BIP39 checks
- keeps optional carving behavior on strong hits
- skips mounted filesystem content scan and extension scan

Example:

```bash
sudo zsh scan_crypto_v5.sh --fast
```

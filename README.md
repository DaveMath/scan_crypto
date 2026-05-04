# scan_cyrpto

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
sudo zsh scan_crypto_v5.sh --no-auto-eject
```

## Outputs

By default, output is written to:
- `/tmp/crypto_scan_v5/summary.txt`
- `/tmp/crypto_scan_v5/results.csv`
- `/tmp/crypto_scan_v5/run.log`

Plus per-partition hit artifacts for deeper review.

## License

MIT

Another DaveMathews.com creation - good luck finding your missing files on those old USB/Thumb/SD drives!

# IOC-Harvester

A lightweight Python tool for Cyber Threat Intelligence (CTI) workflows. IOC-Harvester scans directories of incident reports, threat feeds, and server logs, extracts Indicators of Compromise (IoCs) with strict regular expressions, **defangs** them for safe sharing, and writes a clean, deduplicated JSON database.

Built with the Python standard library only — no external dependencies.

## Features

- **Regex-based extraction** — Identifies IPv4 addresses, MD5/SHA-256 hashes, domains, email addresses, and URLs
- **Defanging** — Output is safe to paste into tickets or chat (`http://evil.com` → `hxxp://evil[.]com`, `1.2.3.4` → `1[.]2[.]3[.]4`)
- **Refang on input** — Automatically normalizes already-defanged IoCs (`hxxp://`, `[.]`) before matching
- **Deduplication** — Order-preserving unique lists per indicator type
- **Batch scanning** — Recursively processes common text and log file extensions

## Requirements

- Python 3.10+

## Installation

Clone the repository and run from the project root:

```bash
git clone https://github.com/YOUR_USERNAME/IOC-Harvester.git
cd IOC-Harvester
```

No `pip install` step is required. The tool runs as a module from the repo directory.

## Quick Start

Scan the included sample incident report:

```bash
python -m ioc_harvester samples/incident_report_dummy.txt -o iocs.json
```

Scan an entire directory (recursive by default):

```bash
python -m ioc_harvester /path/to/reports -o iocs.json
```

Non-recursive scan (files in the top-level folder only):

```bash
python -m ioc_harvester /path/to/reports --no-recursive -o iocs.json
```

### CLI options

| Argument | Description |
|----------|-------------|
| `input` | File or directory to scan |
| `-o`, `--output` | Output JSON path (default: `iocs.json`) |
| `--no-recursive` | Do not scan subdirectories |

## Output format

Results are written as UTF-8 JSON with source file paths, defanged indicators, and counts:

```json
{
  "sources": [
    "/path/to/incident_report_dummy.txt"
  ],
  "indicators": {
    "ipv4": ["203[.]0[.]113[.]77"],
    "md5": ["a1b2c3d4e5f6789012345678abcdef01"],
    "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    "domains": ["evil-corp-phish[.]net"],
    "emails": ["security-alert@evil-corp-phish[.]net"],
    "urls": ["hxxp://malicious-site[.]com/beacon?id=7"]
  },
  "counts": {
    "ipv4": 1,
    "md5": 1,
    "sha256": 1,
    "domains": 1,
    "emails": 1,
    "urls": 1
  }
}
```

## Python API

Use the extractor in your own automation pipelines:

```python
from pathlib import Path
from ioc_harvester import extract_from_text, scan_directory, write_json

# Single string or file contents
text = Path("samples/incident_report_dummy.txt").read_text(encoding="utf-8")
iocs = extract_from_text(text)
print(iocs.ipv4, iocs.sha256)

# Directory batch job
iocs = scan_directory(Path("samples"))
write_json(iocs, Path("iocs.json"))
```

## Supported file types

When scanning directories, these extensions are processed by default:

`.txt` `.log` `.md` `.csv` `.json` `.xml` `.evtx` `.conf` `.cfg` `.ini` `.yml` `.yaml`

## Sample data

`samples/incident_report_dummy.txt` is a **synthetic** incident report (fake IPs, hashes, domains, and URLs) for testing and development. It is not real threat intelligence.

Run the harvester against it to verify your setup:

```bash
python -m ioc_harvester samples -o samples/output_iocs.json
```

## Project structure

```
IOC-Harvester/
├── ioc_harvester/
│   ├── __init__.py      # Public API exports
│   ├── __main__.py      # CLI entry point
│   ├── patterns.py      # Strict regex patterns
│   ├── defang.py        # Defang / refang utilities
│   └── extractor.py     # Scan, dedupe, JSON output
├── samples/
│   └── incident_report_dummy.txt
├── requirements.txt
└── README.md
```

## How defanging works

| Type | Example input | Defanged output |
|------|---------------|-----------------|
| IPv4 | `203.0.113.77` | `203[.]0[.]113[.]77` |
| Domain | `evil.com` | `evil[.]com` |
| URL | `https://evil.com/path` | `hxxps://evil[.]com/path` |
| Email | `user@evil.com` | `user@evil[.]com` |

Defanged IoCs in source material are refanged internally before extraction, then defanged again in the output.

## Disclaimer

This tool uses pattern matching, not threat validation. Extracted values may include false positives (e.g. version strings, documentation examples). Always corroborate IoCs with your TI platform, sandbox, or internal intelligence before blocking or alerting.

Sample data in this repository is fictional and intended for testing only.



"""CLI entry point: python -m ioc_harvester <directory> [-o output.json]"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .extractor import scan_directory, write_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract and defang IoCs from text/log files into JSON.",
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Directory to scan (or single file path)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("iocs.json"),
        help="Output JSON path (default: iocs.json)",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Only scan files directly in the input directory",
    )
    args = parser.parse_args(argv)

    input_path: Path = args.input
    if not input_path.exists():
        print(f"Error: path not found: {input_path}", file=sys.stderr)
        return 1

    if input_path.is_file():
        from .extractor import extract_from_text

        text = input_path.read_text(encoding="utf-8", errors="replace")
        iocs = extract_from_text(text)
        iocs.sources = [str(input_path.resolve())]
    else:
        iocs = scan_directory(input_path, recursive=not args.no_recursive)

    write_json(iocs, args.output)
    counts = iocs.to_dict()["counts"]
    total = sum(counts.values())
    print(f"Wrote {total} indicators to {args.output}")
    for kind, n in counts.items():
        if n:
            print(f"  {kind}: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

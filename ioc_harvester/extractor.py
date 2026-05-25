"""Extract and deduplicate IoCs from text and directories."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import patterns as p
from .defang import (
    defang_domain,
    defang_email,
    defang_ip,
    defang_url,
    refang_text,
)

TEXT_EXTENSIONS = frozenset(
    {".txt", ".log", ".md", ".csv", ".json", ".xml", ".evtx", ".conf", ".cfg", ".ini", ".yml", ".yaml"}
)


@dataclass
class IoCSet:
    ipv4: list[str] = field(default_factory=list)
    md5: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sources": self.sources,
            "indicators": {
                "ipv4": self.ipv4,
                "md5": self.md5,
                "sha256": self.sha256,
                "domains": self.domains,
                "emails": self.emails,
                "urls": self.urls,
            },
            "counts": {
                "ipv4": len(self.ipv4),
                "md5": len(self.md5),
                "sha256": len(self.sha256),
                "domains": len(self.domains),
                "emails": len(self.emails),
                "urls": len(self.urls),
            },
        }


def _dedupe_ordered(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _span_overlaps(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(start >= s and end <= e for s, e in spans)


def _is_valid_domain(domain: str, email_spans: list[tuple[int, int]], start: int, end: int) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld in p.FILE_EXTENSION_TLDS:
        return False
    for es, ee in email_spans:
        if start >= es and end <= ee:
            return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return False
    return True


def extract_from_text(text: str) -> IoCSet:
    normalized = refang_text(text)
    result = IoCSet()

    email_spans: list[tuple[int, int]] = []
    for m in p.EMAIL.finditer(normalized):
        email_spans.append((m.start(), m.end()))
        result.emails.append(defang_email(m.group(0)))

    url_spans: list[tuple[int, int]] = []
    for m in p.URL.finditer(normalized):
        url_spans.append((m.start(), m.end()))
        result.urls.append(defang_url(m.group(0)))

    for m in p.IPV4.finditer(normalized):
        result.ipv4.append(defang_ip(m.group(0)))

    sha_seen: set[str] = set()
    for m in p.SHA256.finditer(normalized):
        val = m.group(0).lower()
        sha_seen.add(val)
        result.sha256.append(val)

    for m in p.MD5.finditer(normalized):
        val = m.group(0).lower()
        if val in sha_seen:
            continue
        result.md5.append(val)

    for m in p.DOMAIN.finditer(normalized):
        domain = m.group(0)
        if _span_overlaps(url_spans, m.start(), m.end()):
            continue
        if not _is_valid_domain(domain, email_spans, m.start(), m.end()):
            continue
        result.domains.append(defang_domain(domain.lower()))

    result.ipv4 = _dedupe_ordered(result.ipv4)
    result.md5 = _dedupe_ordered(result.md5)
    result.sha256 = _dedupe_ordered(result.sha256)
    result.domains = _dedupe_ordered(result.domains)
    result.emails = _dedupe_ordered(result.emails)
    result.urls = _dedupe_ordered(result.urls)
    return result


def merge_sets(target: IoCSet, other: IoCSet) -> None:
    target.ipv4 = _dedupe_ordered([*target.ipv4, *other.ipv4])
    target.md5 = _dedupe_ordered([*target.md5, *other.md5])
    target.sha256 = _dedupe_ordered([*target.sha256, *other.sha256])
    target.domains = _dedupe_ordered([*target.domains, *other.domains])
    target.emails = _dedupe_ordered([*target.emails, *other.emails])
    target.urls = _dedupe_ordered([*target.urls, *other.urls])


def scan_directory(
    root: Path,
    *,
    extensions: frozenset[str] | None = None,
    recursive: bool = True,
) -> IoCSet:
    root = root.resolve()
    ext_filter = extensions or TEXT_EXTENSIONS
    combined = IoCSet()

    paths = root.rglob("*") if recursive else root.glob("*")
    for path in sorted(paths):
        if not path.is_file():
            continue
        if path.suffix.lower() not in ext_filter:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        found = extract_from_text(text)
        merge_sets(combined, found)
        combined.sources.append(str(path))

    combined.sources = _dedupe_ordered(combined.sources)
    return combined


def write_json(iocs: IoCSet, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(iocs.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

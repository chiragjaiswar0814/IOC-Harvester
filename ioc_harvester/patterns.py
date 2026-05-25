"""Strict regex patterns for IoC extraction."""

import re

# Valid IPv4 (each octet 0-255)
IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# MD5 / SHA-256 (hex only, word-bounded)
MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# http(s) and defanged hxxp(s) URLs
URL = re.compile(
    r"\b(?:https?|hxxps?)://[^\s<>\"')\]]+",
    re.IGNORECASE,
)

# Domain labels + TLD (2-63 alpha chars); excludes leading/trailing hyphens per label
DOMAIN = re.compile(
    r"\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+)"
    r"([a-zA-Z]{2,63})\b"
)

EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)

# Refang helpers for already-defanged input
REFANG_DOT = re.compile(r"\[\.\]")
REFANG_PROTOCOL = re.compile(r"hxxps?://", re.IGNORECASE)

# False-positive TLDs when scanning prose / filenames
FILE_EXTENSION_TLDS = frozenset(
    {
        "txt",
        "log",
        "json",
        "xml",
        "csv",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "exe",
        "dll",
        "sys",
        "bat",
        "ps1",
        "py",
        "pyc",
        "cfg",
        "ini",
        "yml",
        "yaml",
        "html",
        "htm",
        "css",
        "js",
        "zip",
        "rar",
        "7z",
        "tar",
        "gz",
        "pcap",
        "evtx",
        "gif",
        "png",
        "jpg",
        "jpeg",
        "svg",
        "ico",
        "woff",
        "woff2",
        "ttf",
        "mp4",
        "mp3",
    }
)

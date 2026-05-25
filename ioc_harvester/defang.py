"""Defang URLs, domains, and IP addresses for safe sharing."""

import re

from .patterns import REFANG_DOT, REFANG_PROTOCOL


def refang_text(text: str) -> str:
    """Normalize defanged IoCs in source text before matching."""
    text = REFANG_PROTOCOL.sub(
        lambda m: m.group(0).lower().replace("hxxp", "http"),
        text,
    )
    return REFANG_DOT.sub(".", text)


def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def defang_url(url: str) -> str:
    """Convert http(s)://host/path to hxxp(s)://host[.]/path style."""
    lower = url.lower()
    if lower.startswith("https://"):
        out = "hxxps://" + url[8:]
    elif lower.startswith("http://"):
        out = "hxxp://" + url[7:]
    elif lower.startswith("hxxps://"):
        out = "hxxps://" + url[8:]
    elif lower.startswith("hxxp://"):
        out = "hxxp://" + url[7:]
    else:
        out = url

    # Defang dots in authority (before first / ? #)
    split_at = len(out)
    for sep in ("/", "?", "#"):
        idx = out.find(sep, out.find("://") + 3)
        if idx != -1:
            split_at = min(split_at, idx)

    authority_start = out.find("://") + 3
    authority = out[authority_start:split_at]
    rest = out[split_at:]
    return out[:authority_start] + authority.replace(".", "[.]") + rest.replace(".", "[.]")


def defang_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local}@{defang_domain(domain)}"

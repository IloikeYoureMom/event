from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_id(*parts: str) -> str:
    h = hashlib.sha256("|".join(p.lower().strip() for p in parts).encode())
    return h.hexdigest()[:24]


@dataclass
class IntelItem:

    category: str
    value: str
    source: str
    source_ref: Optional[str] = None
    collected_at: str = field(default_factory=utcnow_iso)
    first_seen: Optional[str] = None
    tlp: str = "CLEAR"
    confidence: float = 0.5
    tags: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    raw_hash: Optional[str] = None
    redacted: bool = False
    id: str = ""

    def __post_init__(self) -> None:
        self.value = str(self.value).strip()
        if not self.id:
            self.id = stable_id(self.category, self.source, self.value[:512])
        if self.raw_hash is None and self.category not in ("ioc_sha256", "ioc_md5"):
            self.raw_hash = hashlib.sha256(self.value.encode(errors="replace")).hexdigest()

    def key(self) -> str:
        if self.category.startswith("ioc_"):
            canon = normalise_value(self.category, self.value)
            ent = entity_type(canon)
            if ent == "domain":
                host = re.match(r"^(?:https?://)?([\w.-]+)", canon)
                if host:
                    return f"ioc_domain:{host.group(1).lower().removeprefix('www.')}"
            elif ent:
                return f"ioc_{ent}:{canon.lower()}"
            return f"ioc_url:{canon}"
        return f"{self.category}:{normalise_value(self.category, self.value)}"

    @property
    def norm(self) -> str:
        return normalise_value(self.category, self.value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))


_IPv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")
_URL_CREDENTIALS_RE = re.compile(r"^https?://[^/@]+@")
_TRACKING_PARAMS = (
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "ref", "ref_src", "igshid", "_ga", "_gl",
)


def normalise_value(category: str, value: str) -> str:
    v = value.strip()
    if category.startswith("ioc_") or category in ("url", "domain", "ipv4"):
        v = _normalise_ioc(v)
    if category.startswith("ioc_domain") or category == "domain":
        v = v.lower().removeprefix("www.")
    if category in ("ioc_ipv4", "ioc_ipv6", "ipv4"):
        v = v.lower()
    if category in ("ioc_md5", "ioc_sha1", "ioc_sha256"):
        v = v.lower()
    if category == "ioc_url" or category == "url":
        v = _normalise_url(v)
    if category == "actor":
        v = v.lower().replace(" ", "-").replace("_", "-")
    if category == "github_repo":
        m = re.search(r"github\.com[/:]([^/\s]+/[^/\s]+?)(?:\.git)?/?$", v)
        v = m.group(1).lower() if m else v.lower()
    return v


def _normalise_ioc(v: str) -> str:
    v = v.strip().strip("\"'`<>(),;[]{}")
    v = _URL_CREDENTIALS_RE.sub("", v)
    return v


def _normalise_url(v: str) -> str:
    v = v.lower().split("#", 1)[0].rstrip("/")
    if "?" in v:
        base, _, query = v.partition("?")
        kept = []
        for pair in query.split("&"):
            key = pair.split("=", 1)[0]
            if key and key not in _TRACKING_PARAMS:
                kept.append(pair)
        v = base + (("?" + "&".join(sorted(kept))) if kept else "")
    return v


def entity_type(value: str) -> str | None:
    v = value.strip()
    if _IPv4.match(v) and all(int(o) < 256 for o in v.split(".")):
        return "ipv4"
    if re.fullmatch(r"[A-Fa-f0-9]{64}", v):
        return "sha256"
    if re.fullmatch(r"[A-Fa-f0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[A-Fa-f0-9]{32}", v):
        return "md5"
    m = re.match(r"^(?:https?://)?([\w.-]+)", v)
    if m and looks_like(m.group(1), "domain"):
        return "domain"
    return None


def ioc_category(value: str) -> str | None:
    t = entity_type(value)
    if t is None:
        return None
    if t == "domain":
        return "ioc_domain"
    if t in ("md5", "sha1", "sha256"):
        return f"ioc_{t}"
    if t == "ipv4":
        return "ioc_ipv4"
    return None


def looks_like(val: str, kind: str) -> bool:
    if kind == "ipv4":
        return bool(_IPv4.match(val)) and all(int(o) < 256 for o in val.split("."))
    if kind == "sha256":
        return bool(re.fullmatch(r"[a-fA-F0-9]{64}", val))
    if kind == "md5":
        return bool(re.fullmatch(r"[a-fA-F0-9]{32}", val))
    if kind == "domain":
        return bool(re.fullmatch(
            r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}", val))
    return False

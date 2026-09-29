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
        return f"{self.category}:{normalise_value(self.category, self.value)}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))


_IPv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def normalise_value(category: str, value: str) -> str:
    v = value.strip()
    if category.startswith("ioc_domain"):
        return v.lower().removeprefix("www.")
    if category in ("ioc_ipv4", "ioc_ipv6"):
        return v.lower()
    if category in ("ioc_md5", "ioc_sha1", "ioc_sha256"):
        return v.lower()
    if category == "ioc_url":
        return v.lower().rstrip("/")
    if category == "actor":
        return v.lower().replace(" ", "-").replace("_", "-")
    if category == "github_repo":
        m = re.search(r"github\.com[/:]([^/\s]+/[^/\s]+?)(?:\.git)?/?$", v)
        return m.group(1).lower() if m else v.lower()
    return v


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

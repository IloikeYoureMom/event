from __future__ import annotations

import json
import re
from pathlib import Path


def canon_actor(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


DEFAULT_ALIASES: dict[str, list[str]] = {
    "lonelydev": ["lone-loco", "unc3886-a", "unc3886"],
    "shai-hulud": ["the-silent-descent", "npm-worm-2025"],
    "china-nexus-teal": ["unc3764", "earth-kadu", "lotus-blossom"],
    "luminous-moth": ["side-winder", "sidecopy", "stolen-palestine"],
}


class Registry:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.canonical_map: dict[str, str] = {}
        if self.path.exists():
            data = json.loads(self.path.read_text())
            self.canonical_map = {k.lower(): v for k, v in data.items()}

    @classmethod
    def bootstrap(cls, path: str | Path) -> "Registry":
        p = Path(path)
        if not p.exists():
            m: dict[str, str] = {}
            for canon, aliases in DEFAULT_ALIASES.items():
                m[canon] = canon
                for a in aliases:
                    m[a] = canon
            p.write_text(json.dumps(m, indent=2, sort_keys=True))
        return cls(p)

    def resolve(self, name: str) -> str:
        n = canon_actor(name)
        return self.canonical_map.get(n, n)

    def add_alias(self, alias: str, canonical: str) -> None:
        self.canonical_map[canon_actor(alias)] = canon_actor(canonical)
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.canonical_map, indent=2, sort_keys=True))


IOC_CATEGORY_BY_STIX = {
    "IPv4-Addr": "ioc_ipv4", "IPv6-Addr": "ioc_ipv6",
    "Domain-Name": "ioc_domain", "Url": "ioc_url",
    "File": "ioc_sha256", "SHA256-Hash": "ioc_sha256",
    "MD5-HASH": "ioc_md5", "Email-Addr": "ioc_email",
    "Mutex": "ioc_mutex", "AutonomousSystem": "ioc_asn",
}

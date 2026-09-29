from __future__ import annotations

import re
from dataclasses import dataclass, field

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "password_kv": re.compile(
        r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[-_ ]?key|apikey)\b\s*[:=]\s*\S+"),
    "url_credentials": re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"),
    "private_key_block": re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    "bearer": re.compile(r"(?i)\b(authorization\s*[:=]\s*)?bearer\s+[A-Za-z0-9._-]{20,}"),
    "generic_high_entropy": re.compile(
        r"\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|"
        r"glpat-[A-Za-z0-9_-]{20,})\b"),
    "email_local_part": re.compile(r"\b([A-Za-z0-9._%+-]{3,})@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"),
    "phone_us": re.compile(r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)"),
}

MASK = "<<REDACTED>>"


@dataclass
class RedactionResult:
    text: str
    hits: dict[str, int] = field(default_factory=dict)

    @property
    def changed(self) -> bool:
        return bool(self.hits)


def redact_secrets(text: str, mask_email_locals: bool = True) -> RedactionResult:
    res = RedactionResult(text=text)
    out = text
    for name, pat in SECRET_PATTERNS.items():
        if name == "email_local_part" and not mask_email_locals:
            continue

        def _sub(m: re.Match, _n: str = name) -> str:
            res.hits[_n] = res.hits.get(_n, 0) + 1
            if _n == "email_local_part":
                return f"{MASK}@{m.group(2)}"
            if _n == "password_kv":
                key = re.split(r"[:=]", m.group(0))[0]
                return f"{key}{MASK}"
            if _n == "url_credentials":
                scheme, rest = m.group(0).split("://", 1)
                return f"{scheme}://{MASK}@"
            return MASK

        out = pat.sub(_sub, out)
    res.text = out
    return res

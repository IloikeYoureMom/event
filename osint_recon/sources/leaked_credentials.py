from __future__ import annotations

import os
import re
from typing import Iterable

from ..models import IntelItem
from ..redact import redact_secrets
from .base import Collector


class HibpDomainCollector(Collector):

    name = "hibp_domain"
    enabled_by_default = False   # needs paid/verified API key

    def collect(self) -> Iterable[IntelItem]:
        api_key = self.cfg.get("api_key") or os.getenv("HIBP_API_KEY", "")
        if not api_key:
            self.log.info("HIBP skipped: set config.hibp.api_key or $HIBP_API_KEY")
            return
        domains = self.cfg.get("domains", [])
        for d in domains:
            resp = self.http.get(
                f"https://haveibeenpwned.com/api/v3/breacheddomain/{d}",
                headers={"api-key": api_key, "Accept": "application/json"})
            if not resp.ok:
                self.log.warning("HIBP %s failed (%s)", d, resp.error or resp.status)
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            for b in data if isinstance(data, list) else []:
                yield IntelItem(
                    category="leaked_credential",
                    value=f"{b.get('Title', 'unknown breach')} -> {d}",
                    source=self.name, source_ref=b.get("Domain", ""),
                    first_seen=(b.get("BreachDate") or "") + "T00:00:00Z",
                    confidence=0.95, tlp="AMBER",
                    tags=["credential-exposure", "breach"],
                    attributes={
                        "domain": d,
                        "breach_name": b.get("Title"),
                        "compromised_data_classes": b.get("DataClasses", []),
                        "description_redacted": redact_secrets(
                            b.get("Description", "") or "").text,
                    },
                )


class SecsgnTeaserCollector(Collector):

    name = "leak_teasers"
    enabled_by_default = False  # point at a licensed vendor feed instead by default

    def collect(self) -> Iterable[IntelItem]:
        url = self.cfg.get("url")
        if not url:
            self.log.info("leak_teasers: configure an authorised vendor teaser feed url")
            return
        resp = self.http.get(url, headers={"Authorization": f"Bearer {self.cfg.get('token','')}"})
        if not resp.ok:
            self.log.warning("teaser feed failed")
            return
        for rec in resp.json().get("items", []):
            text = f"{rec.get('victim','?')} :: {rec.get('actor','?')} :: {rec.get('size','?')}"
            safe = redact_secrets(text)
            yield IntelItem(
                category="ransom_leak", value=safe.text, source=self.name,
                source_ref=rec.get("link"), first_seen=rec.get("posted"),
                tlp="AMBER", confidence=0.8, tags=["leak-teaser"],
                attributes={"victim": rec.get("victim"), "actor": rec.get("actor"),
                            "redaction_hits": safe.hits},
                redacted=safe.changed,
            )

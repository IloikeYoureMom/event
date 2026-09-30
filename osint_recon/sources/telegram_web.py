from __future__ import annotations

import html
import re
import time
from urllib.parse import urljoin

from ..models import IntelItem
from ..redact import redact_secrets
from .base import Collector, iocs_from_text

MSG_RE = re.compile(
    r'class="tgme_widget_message_text js-message_text[^"]*"[^>]*>(.*?)</div>',
    re.S,
)
DATE_RE = re.compile(r'<time datetime="([^"]+)"')
POST_RE = re.compile(r'data-post="([A-Za-z0-9_]+)/(\d+)"')
LINK_RE = re.compile(
    r'(?:https?://(?:www\.)?t\.me|telegram\.me)/s/([A-Za-z0-9_]+)',
)
ANY_TG_LINK_RE = re.compile(
    r'(?:https?://(?:www\.)?t\.me|telegram\.me)/([A-Za-z0-9_]{4,})',
)
TAG_RE = re.compile(r"<[^>]+>")


class TelegramWebCollector(Collector):

    name = "telegram_web"
    enabled_by_default = True
    BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

    def collect(self):
        channels = [c.strip("/") for c in self.cfg.get("channels", []) if c.strip("/")]
        keywords = [k.lower() for k in self.cfg.get(
            "keywords", ["breach", "stealer", "db", "combo", "panel", "log", "sale"])]
        pages = int(self.cfg.get("pages", 1))
        delay = float(self.cfg.get("delay_seconds", 2.0))
        discover = bool(self.cfg.get("discover_channels", True))
        max_discovered = int(self.cfg.get("max_discovered", 5))
        filter_by_keywords = bool(self.cfg.get("filter_by_keywords", False))

        seen_channels = set(channels)
        queue = list(channels)
        emitted = 0

        while queue:
            ch = queue.pop(0)
            before = None
            for _page in range(pages):
                url = f"https://t.me/s/{ch}"
                if before:
                    url += f"?before={before}"
                try:
                    resp = self.http.get(url, allow_robots_override=True,
                                         headers={"User-Agent": self.BROWSER_UA})
                    body = resp.body if resp.ok else ""
                    if not body:
                        break
                except Exception as exc:
                    self.log.warning("telegram_web %s: %s", ch, exc)
                    break
                blocks = re.split(r'class="tgme_widget_message_wrap', body)[1:]
                if not blocks:
                    break
                for block in reversed(blocks):
                    m = MSG_RE.search(block)
                    text_raw = m.group(1) if m else ""
                    if not text_raw:
                        continue
                    text = html.unescape(TAG_RE.sub(" ", text_raw))
                    text = re.sub(r"\s+", " ", text).strip()
                    low = text.lower()
                    dm = DATE_RE.search(block)
                    msg_date = dm.group(1) if dm else None
                    pm = POST_RE.search(block)
                    msg_id = pm.group(2) if pm else None
                    ref = f"https://t.me/{ch}/{msg_id}" if msg_id else f"https://t.me/s/{ch}"
                    if discover:
                        found_names = LINK_RE.findall(block) + ANY_TG_LINK_RE.findall(block)
                        for found in found_names:
                            found = found.strip("/")
                            bad = {"s", "joinchat", "proxy", "iv", "addstickers",
                                   "share", "setlanguage", "bg", "confirm"}
                            if not found or found.lower() in bad:
                                continue
                            if found.lower() in {c.lower() for c in seen_channels}:
                                continue
                            seen_channels.add(found)
                            if len(queue) < max_discovered:
                                queue.append(found)
                    if filter_by_keywords and keywords and not any(k in low for k in keywords):
                        continue
                    safe = redact_secrets(text[:2000])
                    meta = {"chat": ch, "msg_id": msg_id, "date": msg_date,
                            "redaction_hits": safe.hits}
                    yield IntelItem(
                        category="chat_message", value=safe.text, source=self.name,
                        source_ref=ref, first_seen=msg_date, tlp="CLEAR",
                        confidence=0.5,
                        tags=["telegram", "web-preview"] +
                             [k for k in keywords if k in low],
                        attributes=meta, redacted=safe.changed)
                    emitted += 1
                    for it in iocs_from_text(safe.text, source=f"{self.name}:ioc",
                                             source_ref=ref, tags=["from-chat"]):
                        it.attributes.update(meta)
                        yield it
                ids = POST_RE.findall(body)
                own_ids = [int(n) for name, n in ids if name == ch]
                if own_ids:
                    before = min(own_ids)
                else:
                    break
                time.sleep(delay)

        self.log.info("telegram_web emitted %d chat items from %d channels",
                      emitted, len(seen_channels))

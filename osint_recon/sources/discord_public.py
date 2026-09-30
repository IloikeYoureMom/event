from __future__ import annotations

import re
import time

from ..models import IntelItem
from .base import Collector

INVITE_RE = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord(?:app)?\.com/(?:invite|guild-preview)|"
    r"discord\.(?:gg|io|me|lu))/([A-Za-z0-9_-]{2,})",
)


class DiscordPublicCollector(Collector):

    name = "discord_public"
    enabled_by_default = True

    def _invite(self, code: str):
        url = (f"https://discord.com/api/v10/invites/{code}"
               f"?with_counts=true&with_expiration=true")
        return self.http.get(url, headers={"Accept": "application/json"},
                             allow_robots_override=True)

    def collect(self):
        seeds = list(self.cfg.get("invite_codes", []))
        crawl_pages = int(self.cfg.get("crawl_pages", 1))
        max_seen = int(self.cfg.get("max_invites", 40))
        delay = float(self.cfg.get("delay_seconds", 1.5))
        codes = {c.strip("/").lower() for c in seeds if c.strip("/")}
        all_seen: set[str] = set()
        queue = list(codes)
        emitted = 0

        while queue and len(all_seen) < max_seen:
            code = queue.pop(0)
            if code in all_seen:
                continue
            all_seen.add(code)
            resp = self._invite(code)
            if not resp.ok or resp.status != 200:
                self.log.debug("discord_public invite %s -> %s", code,
                               resp.status or resp.error)
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            guild = data.get("guild") or {}
            gid = str(guild.get("id", ""))
            gname = guild.get("name", "")
            meta = {
                "invite_code": code,
                "guild_id": gid,
                "guild_name": gname,
                "members": data.get("approximate_member_count"),
                "presence": data.get("approximate_presence_count"),
                "vanity_url": data.get("vanity_url"),
                "description": (guild.get("description") or "")[:300],
                "features": guild.get("features", [])[:20],
                "expires_at": data.get("expires_at"),
            }
            first_seen = data.get("created_at") or time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            yield IntelItem(
                category="chat_server", value=f"{gname} ({gid})" if gid else code,
                source=self.name, source_ref=f"https://discord.gg/{code}",
                first_seen=first_seen, tlp="CLEAR", confidence=0.6,
                tags=["discord", "public-invite"] +
                     ([str(data.get("type"))] if data.get("type") else []),
                attributes=meta)
            emitted += 1

            pages_left = crawl_pages
            cursor = None
            while pages_left > 0 and gid:
                pages_left -= 1
                wid_url = f"https://discord.com/api/guilds/{gid}/widget.json"
                if cursor:
                    wid_url += f"?{cursor}"
                wresp = self.http.get(wid_url,
                                      headers={"Accept": "application/json"},
                                      allow_robots_override=True)
                if not wresp.ok or wresp.status != 200:
                    break
                try:
                    widget = wresp.json()
                except Exception:
                    break
                for ch in widget.get("channels", []):
                    for inv in INVITE_RE.findall(str(ch)):
                        inv = inv.lower()
                        if inv not in all_seen and len(queue) < max_seen:
                            queue.append(inv)
                for st in widget.get("users", []):
                    for inv in INVITE_RE.findall(str(st)):
                        inv = inv.lower()
                        if inv not in all_seen and len(queue) < max_seen:
                            queue.append(inv)
                break

            time.sleep(delay)

        self.log.info("discord_public emitted %d server items from %d invites probed",
                      emitted, len(all_seen))

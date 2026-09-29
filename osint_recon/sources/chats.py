from __future__ import annotations

import asyncio
import os
import re
from typing import Iterable

from ..models import IntelItem
from ..redact import redact_secrets
from .base import Collector, iocs_from_text


class TelegramCollector(Collector):

    name = "telegram"
    enabled_by_default = False

    def collect(self) -> Iterable[IntelItem]:
        try:
            from telethon import TelegramClient          # type: ignore
        except ImportError:
            self.log.info("pip install telethon to enable telegram collection")
            return
        api_id = os.getenv("TG_API_ID") or self.cfg.get("api_id", "")
        api_hash = os.getenv("TG_API_HASH") or self.cfg.get("api_hash", "")
        if not (api_id and api_hash):
            self.log.info("telegram: set $TG_API_ID/$TG_API_HASH (my.telegram.org)")
            return
        channels = self.cfg.get("channels", [])       # e.g. ["no_breach_official"]
        keywords = [k.lower() for k in self.cfg.get("keywords", ["breach", "stealer", "db", "combo"])]
        limit = int(self.cfg.get("history_limit", 200))

        async def _run():
            out: list[IntelItem] = []
            client = TelegramClient(os.path.expanduser(self.cfg.get("session", "~/.osint_recon_tg")),
                                    api_id, api_hash)
            await client.start()
            for ch in channels:
                try:
                    async for msg in client.iter_messages(ch, limit=limit):
                        text = msg.message or ""
                        low = text.lower()
                        if not any(k in low for k in keywords):
                            continue
                        safe = redact_secrets(text[:2000])
                        meta = {
                            "chat": str(msg.chat_id), "msg_id": msg.id,
                            "date": msg.date.strftime("%Y-%m-%dT%H:%M:%SZ") if msg.date else None,
                            "redaction_hits": safe.hits,
                        }
                        out.append(IntelItem(
                            category="chat_message", value=safe.text, source=self.name,
                            source_ref=f"https://t.me/{ch}/{msg.id}",
                            first_seen=meta["date"], tlp="CLEAR", confidence=0.55,
                            tags=["telegram"] + [k for k in keywords if k in low],
                            attributes=meta, redacted=safe.changed))
                        for it in iocs_from_text(safe.text, source="telegram:ioc",
                                                 source_ref=meta.get("chat"),
                                                 tags=["from-chat"]):
                            it.attributes.update(meta)
                            out.append(it)
                except Exception as exc:
                    self.log.warning("telegram channel %s: %s", ch, exc)
            await client.disconnect()
            return out

        try:
            yield from asyncio.run(_run())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            yield from loop.run_until_complete(_run())


class DiscordCollector(Collector):

    name = "discord"
    enabled_by_default = False

    def collect(self) -> Iterable[IntelItem]:
        try:
            import discord                                # type: ignore  # pip install discord.py
        except ImportError:
            self.log.info("pip install discord.py to enable discord collection")
            return
        token = os.getenv("DISCORD_BOT_TOKEN") or self.cfg.get("bot_token", "")
        guild_channel_ids = self.cfg.get("channel_ids", {})   # {"123456789": "#intel-drop"}
        if not token or not guild_channel_ids:
            self.log.info("discord: set $DISCORD_BOT_TOKEN + sources.discord.channel_ids")
            return
        keywords = [k.lower() for k in self.cfg.get("keywords", ["c2", "panel", "log", "sale"])]
        limit = int(self.cfg.get("history_limit", 100))

        async def _run():
            intents = discord.Intents.default()
            intents.messages = True
            intents.guilds = True
            client = discord.Client(intents=intents)
            out: list[IntelItem] = []

            @client.event
            async def on_ready():                     # noqa: ANN001
                for cid, label in guild_channel_ids.items():
                    chan = client.get_channel(int(cid))
                    if chan is None:
                        continue
                    async for m in chan.history(limit=limit):
                        text = m.content or ""
                        low = text.lower()
                        if not any(k in low for k in keywords):
                            continue
                        safe = redact_secrets(text[:2000])
                        ref = getattr(m, "jump_url", f"discord://channels/{cid}/{m.id}")
                        out.append(IntelItem(
                            category="chat_message", value=safe.text, source=self.name,
                            source_ref=ref,
                            first_seen=m.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            confidence=0.55, tlp="CLEAR",
                            tags=["discord", label.strip("#")] +
                                 [k for k in keywords if k in low],
                            attributes={"author": str(m.author), "channel": label,
                                        "redaction_hits": safe.hits},
                            redacted=safe.changed))
                await client.close()

            await client.start(token)
            return out

        try:
            yield from asyncio.run(_run())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            yield from loop.run_until_complete(_run())

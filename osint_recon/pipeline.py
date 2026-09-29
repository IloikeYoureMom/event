from __future__ import annotations

import csv
import json
import logging
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import IntelItem, normalise_value
from .registry import Registry
from .redact import redact_secrets

from .sources.ioc_feeds import TextFeedCollector, StixFileCollector
from .sources.threat_reports import RssReportCollector
from .sources.leaked_credentials import HibpDomainCollector, SecsgnTeaserCollector
from .sources.infected_devices import MalwareBazaarBrandCollector, CrtshRogueCertCollector
from .sources.chats import TelegramCollector, DiscordCollector
from .sources.forums import ForumRssCollector
from .sources.ransom_leaks import RansomLeakCollector
from .sources.sec_edgar import EdgarItem105Collector
from .sources.pastes import PublicPasteDumpCollector, RentrySearchCollector
from .sources.github_watch import GithubSearchCollector, GithubIocRepoCollector
from .sources.documents import DocLinkHarvester
from .sources.base import HttpClient

ALL_COLLECTOR_CLASSES = [
    TextFeedCollector, StixFileCollector, RssReportCollector,
    HibpDomainCollector, SecsgnTeaserCollector,
    MalwareBazaarBrandCollector, CrtshRogueCertCollector,
    TelegramCollector, DiscordCollector, ForumRssCollector,
    RansomLeakCollector, EdgarItem105Collector,
    PublicPasteDumpCollector, RentrySearchCollector,
    GithubSearchCollector, GithubIocRepoCollector, DocLinkHarvester,
]


def load_config(path: str | Path) -> dict[str, Any]:
    import yaml
    cfg = yaml.safe_load(Path(path).read_text()) or {}
    return cfg


class Pipeline:
    def __init__(self, cfg: dict[str, Any], base_dir: Path | None = None):
        self.cfg = cfg
        self.base = base_dir or Path(".")
        out = cfg.get("output", {})
        self.data_dir = Path(out.get("data_dir", "data"))
        self.runs_dir = self.data_dir / "runs"
        self.state_dir = self.data_dir / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        http_cfg = cfg.get("http", {})
        self.http = HttpClient(
            user_agent=http_cfg.get("user_agent"),
            respect_robots=http_cfg.get("respect_robots", True),
            min_delay=float(http_cfg.get("min_delay_seconds", 2.0)),
            timeout=float(http_cfg.get("timeout_seconds", 30)),
            retries=int(http_cfg.get("retries", 2)),
        )
        self.registry = Registry.bootstrap(self.state_dir / "actor_aliases.json")

    def build_collectors(self) -> list:
        src_cfg = self.cfg.get("sources", {}) or {}
        only = set(self.cfg.get("_only", []))
        collectors = []
        for cls in ALL_COLLECTOR_CLASSES:
            c = src_cfg.get(cls.name, {}) or {}
            if isinstance(c, bool):
                c = {"enabled": c}
            enabled = c.get("enabled", cls.enabled_by_default)
            if not enabled:
                continue
            if only and cls.name not in only:
                continue
            kwargs: dict[str, Any] = {}
            if cls is RssReportCollector:
                kwargs["registry"] = self.registry
            inst = cls(c, http=self.http, **kwargs)
            collectors.append(inst)
        return collectors

    def run(self) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = self.runs_dir / stamp
        run_dir.mkdir(parents=True, exist_ok=True)
        seen = self._load_seen()
        fresh: list[IntelItem] = []
        dupes = 0
        for col in self.build_collectors():
            logging.getLogger("osint_recon").info("== running %s ==", col.name)
            for it in col.run():
                if it.category in ("forum_post", "chat_message", "paste",
                                   "threat_report", "stealer_log"):
                    safe = redact_secrets(it.value)
                    if safe.changed:
                        it.value = safe.text
                        it.redacted = True
                        it.attributes["redaction_hits"] = safe.hits
                k = it.key()
                if k in seen:
                    dupes += 1
                    continue
                seen.add(k)
                fresh.append(it)
            self._save_seen(seen)
        self._write(run_dir, fresh, dupes)
        return run_dir

    def _write(self, run_dir: Path, items: list[IntelItem], dupes: int) -> None:
        jl = run_dir / "items.jsonl"
        with jl.open("w") as f:
            for it in items:
                f.write(it.to_json() + "\n")
        cs = run_dir / "iocs.csv"
        ioc_items = [i for i in items if i.category.startswith("ioc_")]
        with cs.open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["type", "value", "source", "first_seen", "tlp",
                        "confidence", "tags", "source_ref"])
            for i in sorted(ioc_items, key=lambda x: (x.category, x.value)):
                w.writerow([i.category.removeprefix("ioc_"),
                            normalise_value(i.category, i.value), i.source,
                            i.first_seen or i.collected_at, i.tlp, i.confidence,
                            ";".join(i.tags), i.source_ref or ""])
        md = run_dir / "summary.md"
        by_cat: Counter = Counter(i.category for i in items)
        by_src: Counter = Counter(i.source.split(":")[0] for i in items)
        alerts = defaultdict(list)
        watch = [w.lower() for w in (self.cfg.get("watch_terms") or [])]
        for i in items:
            hay = (i.value + " " + json.dumps(i.attributes, default=str)).lower()
            for w in watch:
                if w in hay:
                    alerts[w].append(i)
        lines = [f"# OSINT recon run {run_dir.name}", "",
                 f"* total new items: **{len(items)}** (dupes skipped: {dupes})",
                 f"* IOC items: **{len(ioc_items)}**", "", "## By category", ""]
        lines += [f"- `{c}`: {n}" for c, n in by_cat.most_common()]
        lines += ["", "## By source", ""] + [f"- `{s}`: {n}" for s, n in by_src.most_common()]
        if watch:
            lines += ["", "## Watch-term hits", ""]
            for w, its in alerts.items():
                lines.append(f"### `{w}` — {len(its)} hit(s)")
                for it in its[:15]:
                    ref = it.source_ref or ""
                    lines.append(f"- [{it.category}] {it.value[:120]} ({ref})")
                lines.append("")
        md.write_text("\n".join(lines))

    @property
    def seen_file(self) -> Path:
        return self.state_dir / "seen_keys.txt"

    def _load_seen(self) -> set[str]:
        if self.seen_file.exists():
            return set(self.seen_file.read_text().splitlines())
        return set()

    def _save_seen(self, seen: set[str]) -> None:
        tmp = self.seen_file.with_suffix(".tmp")
        tmp.write_text("\n".join(sorted(seen)))
        tmp.replace(self.seen_file)


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr)

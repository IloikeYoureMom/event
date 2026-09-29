from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Iterable

from ..models import IntelItem
from .base import Collector

API = "https://api.github.com"


class GithubSearchCollector(Collector):
    name = "github_repos"

    DEFAULT_QUERIES = [
        "shai-hulud", "trivyvix", "npm-worm", "s1ngularity",
        '"config.npmrc" AND "publishConfig"',   # worm-published package tell
    ]

    def collect(self) -> Iterable[IntelItem]:
        token = os.getenv("GITHUB_TOKEN") or self.cfg.get("token", "")
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        else:
            self.log.info("no GITHUB_TOKEN: unauthenticated rate limit (10/min)")
        queries = list(self.DEFAULT_QUERIES) + list(self.cfg.get("queries", []))
        since = self.cfg.get("since", "")      # ISO date, e.g. created:>2025-09-01
        for q in queries:
            full = f"{q} {('created:>=' + since) if since else ''}".strip()
            url = f"{API}/search/repositories?q={full.replace(' ', '+')}&sort=updated&per_page=30"
            resp = self.http.get(url, headers=headers)
            if not resp.ok:
                self.log.warning("gh search %r failed (%s)", q, resp.error or resp.status)
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            for r in data.get("items", []):
                yield IntelItem(
                    category="github_repo", value=r["full_name"], source=self.name,
                    source_ref=r["html_url"], first_seen=r.get("created_at"),
                    confidence=0.6, tlp="CLEAR", tags=["github", f"query:{q}"],
                    attributes={"description": (r.get("description") or "")[:400],
                                "stars": r.get("stargazers_count"),
                                "owner_type": r.get("owner", {}).get("type"),
                                "pushed_at": r.get("pushed_at"),
                                "topics": r.get("topics", [])[:10]},
                )


class GithubIocRepoCollector(Collector):

    name = "github_ioc_repos"

    DEFAULT_REPOS = ["digitalside/threat-actor"]

    def collect(self) -> Iterable[IntelItem]:
        repos = self.cfg.get("repos", self.DEFAULT_REPOS)
        cache = Path(self.cfg.get("cache_dir", "data/cache/git"))
        cache.mkdir(parents=True, exist_ok=True)
        from .ioc_feeds import StixFileCollector, TextFeedCollector
        stix = StixFileCollector({"cache_dir": str(cache)}, http=self.http)
        for repo in repos:
            dest = cache / repo.replace("/", "__")
            if dest.exists():
                ok = self._git(dest, "pull", "--ff-only")
            else:
                ok = self._git(None, "clone", "--depth", "1",
                               f"https://github.com/{repo}.git", str(dest))
            if not ok:
                self.log.warning("git failed for %s", repo)
                continue
            newest: list[Path] = []
            for p in dest.rglob("*"):
                if p.is_file() and p.suffix in (".stix", ".json", ".txt", ".csv") \
                        and p.stat().st_size < 50_000_000:
                    newest.append(p)
            for p in newest[:int(self.cfg.get("max_files", 50))]:
                if p.name.endswith((".stix", ".json")):
                    yield from stix._ingest_path(p)
                else:
                    body = p.read_text(errors="replace")[:2_000_000]
                    from .base import iocs_from_text
                    for it in iocs_from_text(body, source=f"{self.name}:{repo}",
                                             source_ref=str(p.relative_to(dest)),
                                             tags=["git-repo", repo.split('/')[-1]]):
                        yield it

    @staticmethod
    def _git(cwd: Path | None, *args: str) -> bool:
        try:
            r = subprocess.run(["git", *args], cwd=str(cwd) if cwd else None,
                               capture_output=True, timeout=180)
            return r.returncode == 0
        except Exception:
            return False

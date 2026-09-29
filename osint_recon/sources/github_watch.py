from __future__ import annotations

import io
import json
import os
import re
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

from ..models import IntelItem
from .base import Collector

API = "https://api.github.com"
RATE_LIMIT_HEADERS = ("x-ratelimit-limit", "x-ratelimit-remaining", "retry-after")


class GithubSearchCollector(Collector):
    name = "github_repos"

    DEFAULT_QUERIES = [
        "shai-hulud", "trivyvix", "npm-worm", "s1ngularity",
        '"config.npmrc" AND "publishConfig"',
    ]

    def _headers(self) -> dict[str, str]:
        token = os.getenv("GITHUB_TOKEN") or self.cfg.get("token", "")
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _note_rate_limit(self, resp) -> None:
        low = {k.lower(): v for k, v in resp.headers.items()}
        rem = low.get("x-ratelimit-remaining")
        lim = low.get("x-ratelimit-limit")
        if rem is not None and lim not in (None, "60"):
            self.log.info("github api remaining=%s/%s", rem, lim)

    def collect(self) -> Iterable[IntelItem]:
        token = os.getenv("GITHUB_TOKEN") or self.cfg.get("token", "")
        headers = self._headers()
        if not token:
            self.log.info("no GITHUB_TOKEN: unauthenticated rate limit (10/min)")
        queries = list(self.DEFAULT_QUERIES) + list(self.cfg.get("queries", []))
        since = self.cfg.get("since", "")
        urls = []
        for q in queries:
            full = f"{q} {('created:>=' + since) if since else ''}".strip()
            urls.append((q, f"{API}/search/repositories?q={quote(full)}&sort=updated&per_page=30"))
        resps = self.http.get_many([u for _, u in urls], headers=headers,
                                   skip_rate_limit=bool(token))
        for (q, _), resp in zip(urls, resps):
            self._note_rate_limit(resp)
            if not resp.ok:
                self.log.warning("gh search %r failed (%s)", q, resp.error or resp.status)
                if resp.status == 403 or resp.status == 429:
                    break
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

    DEFAULT_REPOS: list[str] = []

    def collect(self) -> Iterable[IntelItem]:
        repos = self.cfg.get("repos", self.DEFAULT_REPOS)
        cache = Path(self.cfg.get("cache_dir", "data/cache/git"))
        cache.mkdir(parents=True, exist_ok=True)
        from .ioc_feeds import StixFileCollector, TextFeedCollector
        stix = StixFileCollector({"cache_dir": str(cache)}, http=self.http)
        for repo in repos:
            dest = cache / repo.replace("/", "__")
            ok = self._git(dest, repo)
            if not ok:
                ok = self._tarball_fallback(repo, dest)
            if not ok:
                self.log.warning("could not obtain %s via git or tarball", repo)
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

    def _git(self, dest: Path, repo: str) -> bool:
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        try:
            if dest.exists():
                r = subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"],
                                   capture_output=True, timeout=180, env=env)
            else:
                r = subprocess.run(["git", "clone", "--depth", "1", "--",
                                    f"https://github.com/{repo}.git", str(dest)],
                                   capture_output=True, timeout=180, env=env)
            return r.returncode == 0
        except Exception:
            return False

    def _tarball_fallback(self, repo: str, dest: Path) -> bool:
        token = os.getenv("GITHUB_TOKEN") or self.cfg.get("token", "")
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        meta = self.http.get(f"{API}/repos/{repo}", headers=headers,
                             skip_rate_limit=bool(token))
        if not meta.ok:
            return False
        try:
            sha = meta.json()["object"]["sha"]
            url = meta.json()["tarball_url"]
        except Exception:
            return False
        stamp = dest.parent / f".{dest.name}.sha"
        if stamp.exists() and stamp.read_text().strip() == sha and dest.exists():
            return True
        blob = self.http.get(url, allow_robots_override=True)
        if not blob.ok:
            return False
        import shutil
        staging = dest.parent / f".{dest.name}.new.{os.getpid()}"
        try:
            staging.mkdir(parents=True, exist_ok=True)
            with tarfile.open(fileobj=io.BytesIO(blob.body.encode(errors="replace")),
                              mode="r:*") as tf:
                tf.extractall(staging, filter="data")
            inner = [p for p in staging.iterdir() if p.is_dir()]
            src = inner[0] if len(inner) == 1 else staging
            if dest.exists():
                shutil.rmtree(dest)
            src.replace(dest)
            stamp.write_text(sha)
            return True
        except Exception as exc:
            self.log.warning("tarball unpack failed for %s: %s", repo, exc)
            return False
        finally:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

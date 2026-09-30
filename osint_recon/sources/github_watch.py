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

RAW_BASES = (
    "https://raw.githubusercontent.com/{repo}/HEAD/{path}",
    "https://github.com/{repo}/raw/HEAD/{path}",
)

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(
        r"(?i)aws.{0,25}?(?:secret|private).{0,25}?['\"\s:=]{1,5}[\"']?([0-9a-zA-Z/+=]{40})[\"']?")),
    ("gcp_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("gcp_oauth_client_id", re.compile(r"\b[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com\b")),
    ("stripe_live_key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("stripe_test_key", re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b")),
    ("stripe_publishable_key", re.compile(r"\bpk_(?:live|test)_[0-9a-zA-Z]{24,}\b")),
    ("openai_key", re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b|\bsk-[A-Za-z0-9]{40,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("deepseek_key", re.compile(r"\bsk-[0-9a-f]{32}\b")),
    ("github_pat_classic", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("github_pat_fine_grained", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b")),
    ("github_oauth_token", re.compile(r"\bgho_[0-9A-Za-z]{36}\b")),
    ("github_server_token", re.compile(r"\bghs_[0-9A-Za-z]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]/B[0-9A-Za-z_]/[0-9A-Za-z_]+")),
    ("discord_bot_token", re.compile(
        r"\b[MA][A-Za-z0-9_-]{22,27}\.[A-Za-z0-9_-]{6,8}\.[A-Za-z0-9_-]{27,40}\b")),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b")),
    ("sendgrid_key", re.compile(r"\bSG\.[0-9A-Za-z_\-]{20,34}\.[0-9A-Za-z_\-]{43}\b")),
    ("twilio_key", re.compile(r"\bAC[0-9a-f]{32}\b")),
    ("mailgun_key", re.compile(r"\bkey-[0-9a-f]{32}\b")),
    ("npm_token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    ("pypi_token", re.compile(r"\b(?:pypi-|wo-)[A-Za-z0-9._\-]{50,}\b")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("shopify_token", re.compile(r"\bshp(at|ca|pa|ed)_[0-9a-f]{32}\b")),
    ("private_key_pem", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("generic_secret_assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|"
        r"client[_-]?secret|private[_-]?token|db[_-]?password|passwd)\b\s*[:=]\s*"
        r"[\"']?([^'\"\s]{16,80})[\"']?")),
]

SKIP_DIR_PARTS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar",
                 ".jar", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".min.js", ".min.css",
                 ".map", ".so", ".dll", ".exe", ".pyc"}
MAX_BLOB_BYTES = 400_000
ENTROPY_MIN = 3.3


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * __import__("math").log2(c / n) for c in counts.values())


def _mask(v: str) -> str:
    v = v.strip().strip("'\";,)]}")
    if len(v) <= 8:
        return "*" * len(v)
    return f"{v[:4]}{'*' * min(12, len(v) - 8)}{v[-4:]}"


def scan_text(text: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    seen_spans: set[tuple[int, int]] = set()
    for kind, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            span = (m.start(), m.end())
            if any(span[0] < e and s < span[1] for s, e in seen_spans):
                continue
            val = m.group(1) if m.groups() and m.group(1) else m.group(0)
            val = val.strip().strip("'\";,)]}")
            if not val:
                continue
            if kind == "generic_secret_assignment":
                low = val.lower()
                if low.startswith(("your", "xxx", "<", "${", "%(", "changeme", "example")):
                    continue
                if "placeholder" in low or "insert" in low or low.count("*") > 4:
                    continue
                if len(val) < 16 or _shannon_entropy(val) < ENTROPY_MIN:
                    continue
            if val.startswith("eyJ") and kind != "jwt_token":
                continue
            if val.rstrip("=").replace("+", "").replace("/", "").isdigit():
                continue
            if kind == "private_key_pem":
                val = "PRIVATE_KEY_BLOCK"
            seen_spans.add(span)
            hits.append((kind, val))
    return hits


class GithubSearchCollector(Collector):
    name = "github_repos"

    WATCH_REPOS = [
        "digitalside/threat-actor",
        "brianklaas/Threat-Actor-Name-Database",
        "centerforsecurityanddemocracy/public_threat_lists",
        "blackorbird/APT_REPORT",
        "nradwinski/threat-actor-json",
        "0x4d31/awesome-osint",
    ]

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
        for extra in list(self.WATCH_REPOS) + list(self.cfg.get("repos", [])):
            yield IntelItem(
                category="github_repo", value=extra, source=self.name,
                source_ref=f"https://github.com/{extra}",
                confidence=0.5, tlp="CLEAR", tags=["github", "watchlist"],
                attributes={"description": "", "stars": None,
                            "owner_type": "Organization", "pushed_at": None,
                            "topics": []},
            )
        if not token:
            self.log.info("no GITHUB_TOKEN: search endpoint needs external API credentials; watchlist only")
            return
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


class GithubSecretScanCollector(Collector):

    name = "github_secrets"

    WATCH_REPOS = [
        "digitalside/threat-actor",
        "brianklaas/Threat-Actor-Name-Database",
        "centerforsecurityanddemocracy/public_threat_lists",
        "blackorbird/APT_REPORT",
        "nradwinski/threat-actor-json",
        "0x4d31/awesome-osint",
    ]

    DEFAULT_QUERIES = [
        '"shai-hulud" OR "npm-worm" OR "trivyvix"',
        '"config.npmrc" "publishConfig"',
    ]

    def _headers(self) -> dict[str, str]:
        token = os.getenv("GITHUB_TOKEN") or self.cfg.get("token", "")
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _code_search(self, q: str) -> list[dict]:
        url = f"{API}/search/code?q={quote(q)}&per_page=50"
        resp = self.http.get(url, headers=self._headers(),
                             skip_rate_limit=bool(self._headers().get("Authorization")))
        if not resp.ok:
            self.log.warning("gh code search %r failed (%s)", q, resp.error or resp.status)
            return []
        try:
            return resp.json().get("items", [])
        except Exception:
            return []

    def _repo_paths(self, full_name: str) -> list[str]:
        token_hdrs = self._headers()
        meta = self.http.get(f"{API}/repos/{full_name}", headers=token_hdrs,
                             skip_rate_limit=bool(token_hdrs.get("Authorization")))
        branch = "HEAD"
        if meta.ok:
            try:
                branch = meta.json().get("default_branch", "HEAD")
            except Exception:
                pass
        tree_url = f"{API}/repos/{full_name}/git/trees/{quote(branch)}?recursive=1"
        tree = self.http.get(tree_url, headers=token_hdrs,
                             skip_rate_limit=bool(token_hdrs.get("Authorization")))
        paths: list[str] = []
        if tree.ok:
            try:
                for t in tree.json().get("tree", []):
                    if t.get("type") != "blob":
                        continue
                    p = t.get("path", "")
                    parts = p.split("/")
                    if any(x in SKIP_DIR_PARTS for x in parts):
                        continue
                    if any(p.endswith(s) for s in SKIP_SUFFIXES):
                        continue
                    size = int(t.get("size") or 0)
                    if size > MAX_BLOB_BYTES:
                        continue
                    paths.append(p)
            except Exception:
                paths = []
        if not paths:
            meta2 = self.http.get(f"{API}/repos/{full_name}/contents", headers=token_hdrs,
                                  skip_rate_limit=bool(token_hdrs.get("Authorization")))
            if meta2.ok:
                try:
                    for t in meta2.json():
                        if t.get("type") == "file":
                            paths.append(t["path"])
                except Exception:
                    pass
        if not paths:
            paths = [".env", ".env.production", ".env.local", "config.json",
                     "settings.json", "credentials.yml", "secrets.yaml",
                     "server.js", "app.py", "index.php", "deploy.sh"]
        return paths[: int(self.cfg.get("max_tree_files", 300))]

    def collect(self) -> Iterable[IntelItem]:
        for extra in self.WATCH_REPOS:
            yield IntelItem(
                category="github_repo", value=extra, source=self.name,
                source_ref=f"https://github.com/{extra}",
                confidence=0.5, tlp="CLEAR", tags=["github", "watchlist"],
                attributes={"description": "", "stars": None,
                            "owner_type": "Organization", "pushed_at": None,
                            "topics": []},
            )
        queries = list(self.DEFAULT_QUERIES) + list(self.cfg.get("queries", []))
        max_repos = int(self.cfg.get("max_repos", 25))
        repos: dict[str, str] = {}
        if self.cfg.get("use_code_search", True):
            for q in queries:
                for item in self._code_search(q):
                    fn = item.get("repository", {}).get("full_name", "")
                    if fn and fn not in repos:
                        repos[fn] = q
                    if len(repos) >= max_repos:
                        break
                if len(repos) >= max_repos:
                    break
        for extra in self.cfg.get("repos", []):
            repos.setdefault(extra, "watchlist")
        targets = list(repos.items())[:max_repos]
        jobs = []
        for fn, why in targets:
            paths = self._repo_paths(fn)
            interesting = [p for p in paths if re.search(
                r"(?i)(^|/)\.env[\w.-]*$|(^|/)[\w.-]*(secret|credential|config|settings|token|"
                r"apikey|api_key|deploy|docker-compose|ini|cfg|test|fixture|example)[\w.-]*"
                r"\.(?:ya?ml|json|toml|ini|cfg|conf|py|js|ts|go|rb|php|sh|md|txt|properties)$", p)]
            ordered = (interesting + paths)[: int(self.cfg.get("max_files_per_repo", 40))]
            for path in ordered:
                url = RAW_BASES[0].format(repo=fn, path=path.replace("%2F", "/"))
                jobs.append((fn, why, path, url))
        resps = self.http.get_many([u for *_, u in jobs], skip_rate_limit=True)
        emitted: set[tuple[str, str]] = set()
        for (fn, why, path, url), resp in zip(jobs, resps):
            if not resp.ok or resp.status != 200:
                continue
            body = resp.body or ""
            if "\x00" in body[:2048]:
                continue
            for kind, val in scan_text(body[:MAX_BLOB_BYTES]):
                key = (kind, stable_fingerprint(val))
                if key in emitted:
                    continue
                emitted.add(key)
                yield IntelItem(
                    category="exposed_secret", value=_mask(val), source=self.name,
                    source_ref=f"https://github.com/{fn}/blob/HEAD/{path}",
                    confidence=0.9 if kind != "generic_secret_assignment" else 0.6,
                    tlp="AMBER", redacted=True,
                    tags=["github", "secret", kind, f"query:{why}"],
                    attributes={"repo": fn, "path": path, "secret_type": kind,
                                "line_hint": body[:body.find(val)].count("\n") + 1},
                )


def stable_fingerprint(v: str) -> str:
    import hashlib
    return hashlib.sha256(v.encode(errors="replace")).hexdigest()[:16]

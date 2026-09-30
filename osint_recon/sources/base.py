from __future__ import annotations

import logging
import random
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from ..models import IntelItem

log = logging.getLogger("osint_recon")


def ua_needs_contact(url: str) -> bool:
    host = urllib.parse.urlsplit(url).netloc.lower()
    return host.endswith(("sec.gov",))


class RateLimiter:

    _lock = threading.Lock()

    def __init__(self, min_delay: float = 2.0):
        self.min_delay = min_delay
        self._next_ok: dict[str, float] = {}

    def wait(self, url: str) -> None:
        host = urllib.parse.urlsplit(url).netloc
        with self._lock:
            now = time.monotonic()
            due = self._next_ok.get(host, 0.0)
            delay = max(0.0, due - now) + self.min_delay * random.uniform(0.85, 1.35)
            self._next_ok[host] = now + delay
        if delay:
            time.sleep(delay)


_ROBOTS_CACHE: dict[str, tuple[float, Optional[urllib.robotparser.RobotFileParser]]] = {}


def robots_allows(url: str, ua: str, cache_ttl: float = 3600.0) -> bool:
    parts = urllib.parse.urlsplit(url)
    robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
    hit = _ROBOTS_CACHE.get(robots_url)
    if hit and hit[0] > time.time():
        rp = hit[1]
    else:
        rp = None
        try:
            req = urllib.request.Request(
                robots_url, headers={"User-Agent": ua}, )
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode(errors="replace")
            if "<html" in raw[:200].lower() and "user-agent" not in raw.lower():
                rp = None
            else:
                rp = urllib.robotparser.RobotFileParser()
                rp.parse(raw.splitlines())
        except Exception:
            rp = None
        _ROBOTS_CACHE[robots_url] = (time.time() + cache_ttl, rp)
    if rp is None:
        return True
    return rp.can_fetch(ua, url)


class Collector:

    name: str = "base"
    enabled_by_default: bool = True

    def __init__(self, cfg: dict[str, Any], http: "HttpClient | None" = None):
        self.cfg = cfg or {}
        self.http = http or HttpClient(user_agent=self.cfg.get("user_agent"))
        self.log = logging.getLogger(f"osint_recon.{self.name}")

    def item(self, category: str, value: str, **kw: Any) -> IntelItem:
        kw.setdefault("source", self.name)
        return IntelItem(category=category, value=value, **kw)

    def collect(self) -> Iterable[IntelItem]:
        raise NotImplementedError

    def run(self) -> list[IntelItem]:
        out: list[IntelItem] = []
        try:
            for it in self.collect():
                out.append(it)
        except Exception as exc:
            self.log.error("collector %s failed: %s", self.name, exc)
        self.log.info("collector %s -> %d items", self.name, len(out))
        return out


class HttpClient:

    DEFAULT_UA = "osint-recon/0.1 (threat-intel research tool; contact=<set me>)"

    def __init__(self, user_agent: str | None = None,
                 respect_robots: bool = True, min_delay: float = 2.0,
                 timeout: float = 30.0, retries: int = 2, max_workers: int = 8,
                 max_bytes: int = 64 * 1024 * 1024):
        self.ua = user_agent or self.DEFAULT_UA
        self.respect_robots = respect_robots
        self.limiter = RateLimiter(min_delay)
        self.timeout = timeout
        self.retries = retries
        self.max_workers = max_workers
        self.max_bytes = max_bytes
        self._pool: dict[str, Any] = {}
        self._pool_lock = threading.Lock()

    def _get_pool(self, scheme: str):
        with self._pool_lock:
            if scheme not in self._pool:
                import urllib3
                self._pool[scheme] = urllib3.PoolManager(
                    num_pools=self.max_workers, maxsize=self.max_workers,
                    timeout=urllib3.Timeout(connect=min(10.0, self.timeout),
                                            read=self.timeout),
                    retries=False)
            return self._pool[scheme]

    def get(self, url: str, headers: dict[str, str] | None = None,
            allow_robots_override: bool = False,
            skip_rate_limit: bool = False) -> "HttpResponse":
        if self.respect_robots and not allow_robots_override \
                and not robots_allows(url, self.ua):
            return HttpResponse(url=url, status=0, error="blocked-by-robots.txt")
        last_err: str = ""
        for attempt in range(self.retries + 1):
            if not skip_rate_limit:
                self.limiter.wait(url)
            try:
                return self._fetch_once(url, headers)
            except Exception as exc:
                last_err = str(exc)
                if isinstance(exc, urllib.error.HTTPError) and exc.code == 403:
                    break
                time.sleep((2 ** attempt) + random.random())
        return HttpResponse(url=url, status=0, error=last_err)

    def cached_get(self, url: str, cache_dir: str | Path,
                   headers: dict[str, str] | None = None,
                   ttl_seconds: float = 3600.0,
                   force: bool = False,
                   allow_robots_override: bool = False) -> "HttpResponse":
        import hashlib
        cdir = Path(cache_dir)
        cdir.mkdir(parents=True, exist_ok=True)
        key = hashlib.sha256(url.encode()).hexdigest()[:32]
        meta_path = cdir / f"{key}.meta"
        body_path = cdir / f"{key}.bin"
        if not force and body_path.exists():
            fresh = False
            try:
                etag = mtime = ""
                if meta_path.exists():
                    etag, _, mtime = meta_path.read_text().partition("\n")
                if mtime:
                    req_headers = {"If-Modified-Since": mtime}
                    if etag:
                        req_headers["If-None-Match"] = etag
                    resp = self.get(url, {**req_headers, **(headers or {})},
                              allow_robots_override=allow_robots_override)
                    if resp.status == 304:
                        fresh = True
                        resp = HttpResponse(url=url, status=200,
                                            body=body_path.read_bytes().decode(errors="replace"))
                    elif resp.ok:
                        fresh = True
                        new_etag = resp.headers.get("ETag", "")
                        new_m = resp.headers.get("Last-Modified", "") or mtime
                        meta_path.write_text(f"{new_etag}\n{new_m}")
                        body_path.write_bytes(resp.body.encode(errors="replace"))
                else:
                    age = time.time() - body_path.stat().st_mtime
                    if age < ttl_seconds:
                        fresh = True
                        resp = HttpResponse(url=url, status=200,
                                            body=body_path.read_text(errors="replace"))
                    else:
                        resp = self.get(url, headers, allow_robots_override=allow_robots_override)
                        if resp.ok:
                            fresh = True
                            meta_path.write_text(f"{resp.headers.get('ETag', '')}\n"
                                                 f"{resp.headers.get('Last-Modified', '')}")
                            body_path.write_bytes(resp.body.encode(errors="replace"))
            except Exception:
                fresh = False
            if fresh:
                return resp
        resp = self.get(url, headers, allow_robots_override=allow_robots_override)
        if resp.ok:
            meta_path.write_text(f"{resp.headers.get('ETag', '')}\n"
                                 f"{resp.headers.get('Last-Modified', '')}")
            body_path.write_bytes(resp.body.encode(errors="replace"))
        return resp

    def get_many(self, urls: list[str],
                 headers: dict[str, str] | None = None,
                 skip_rate_limit: bool = False) -> list["HttpResponse"]:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, len(urls)))) as ex:
            return list(ex.map(
                lambda u: self.get(u, headers, skip_rate_limit=skip_rate_limit), urls))

    def post_form(self, url: str, data: str,
                  headers: dict[str, str] | None = None) -> "HttpResponse":
        return self._request(url, data.encode(), {"Content-Type": "application/x-www-form-urlencoded",
                                                  **(headers or {})})

    def _fetch_once(self, url: str, headers: dict[str, str] | None) -> "HttpResponse":
        return self._request(url, None, headers)

    def _request(self, url: str, data: bytes | None,
                 headers: dict[str, str] | None) -> "HttpResponse":
        parts = urllib.parse.urlsplit(url)
        scheme = parts.scheme or "https"
        target = urllib.parse.urlunsplit(("", "", parts.path or "/",
                                          parts.query, parts.fragment))
        req_headers = {
            "User-Agent": self.ua,
            "Accept": "*/*",
            "Host": parts.netloc,
        }
        if headers:
            req_headers.update(headers)
        pool = self._get_pool(scheme)
        resp = pool.request("POST" if data is not None else "GET",
                            f"{scheme}://{parts.netloc}{target}",
                            body=data, headers=req_headers, preload_content=False)
        try:
            raw = resp.read(self.max_bytes)
        finally:
            resp.close()
        charset = resp.headers.get("Content-Type", "")
        enc = ""
        m = re.search(r"charset=([\w-]+)", charset)
        if m:
            enc = m.group(1)
        body = raw.decode(enc or "utf-8", errors="replace")
        final_url = resp.headers.get("X-Url") or url
        if 300 <= resp.status < 400 and resp.headers.get("Location"):
            loc = urllib.parse.urljoin(url, resp.headers["Location"])
            return self._request(loc, data, headers)
        return HttpResponse(url=final_url, status=resp.status,
                            body=body, headers=dict(resp.headers))


class HttpResponse:
    def __init__(self, url: str, status: int, body: str = "",
                 headers: dict[str, str] | None = None, error: str = ""):
        self.url = url
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.error = error

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400 and not self.error

    def json(self) -> Any:
        import json
        return json.loads(self.body)


RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_URL = re.compile(r"https?://[^\s\"'<>()\[\]+,;]+")
RE_DOMAIN_IN_TEXT = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|biz|xyz|top|ru|cn|io|co|me|su|onion|click|live|shop|online|"
    r"site|store|tech|dev|app|vip|club|network|systems|cloud)\b")


def iocs_from_text(text: str, source: str, source_ref: str | None = None,
                   tags: list[str] | None = None) -> list[IntelItem]:
    items: list[IntelItem] = []
    t = tags or []

    def add(cat: str, val: str) -> None:
        items.append(IntelItem(category=cat, value=val, source=source,
                               source_ref=source_ref, tags=list(t)))

    seen_ip = set()
    for m in RE_IPV4.finditer(text):
        ip = m.group(0)
        if all(int(o) < 256 for o in ip.split(".")) and ip not in seen_ip:
            seen_ip.add(ip)
            add("ioc_ipv4", ip)
    for m in RE_SHA256.finditer(text):
        add("ioc_sha256", m.group(0).lower())
    for m in RE_MD5.finditer(text):
        if not RE_SHA256.search(m.group(0)):
            add("ioc_md5", m.group(0).lower())
    for m in RE_URL.finditer(text):
        add("ioc_url", m.group(0))
    for m in RE_DOMAIN_IN_TEXT.finditer(text):
        d = m.group(0).lower().removeprefix("www.")
        if not any(d in u for u in seen_ip):
            add("ioc_domain", d)
    return items

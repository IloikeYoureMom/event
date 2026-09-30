from __future__ import annotations

import csv
import html as html_mod
import io
import json
import re
from typing import Iterable

from ..models import IntelItem, stable_id
from .base import Collector, iocs_from_text


def _strip_tags(text: str) -> str:
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    return html_mod.unescape(text)


class OpenPhishCollector(Collector):

    name = "openphish_feeds"
    enabled_by_default = True

    URLS = ["https://openphish.com/feed.txt"]

    def collect(self) -> Iterable[IntelItem]:
        out: list[IntelItem] = []
        for url in self.cfg.get("urls") or self.URLS:
            resp = self.http.cached_get(url, "data/cache", ttl_seconds=600,
                                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
                                        allow_robots_override=True)
            if not resp.ok:
                self.log.warning("openphish feed %s failed: %s status=%s",
                                 url, resp.error, resp.status)
                continue
            for line in resp.body.splitlines():
                u = line.strip()
                if u.startswith("http"):
                    out.append(self.item("ioc_url", u, source_ref=url,
                                         tags=["phishing", "openphish"],
                                         confidence=0.7))
        return out


class UrlhausDumpCollector(Collector):

    name = "urlhaus_dump"
    enabled_by_default = True

    URLS = ["https://urlhaus.abuse.ch/downloads/text_recent/"]

    def collect(self) -> Iterable[IntelItem]:
        out: list[IntelItem] = []
        for url in self.cfg.get("urls") or self.URLS:
            resp = self.http.cached_get(url, "data/cache", ttl_seconds=600,
                                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
                                        allow_robots_override=True)
            if not resp.ok:
                self.log.warning("urlhaus dump %s failed: %s status=%s",
                                 url, resp.error, resp.status)
                continue
            for line in resp.body.splitlines():
                u = line.strip()
                if u.startswith("http"):
                    out.append(self.item("ioc_url", u, source_ref=url,
                                         tags=["malware-payload", "urlhaus"],
                                         confidence=0.9))
        return out


class PhishTankCollector(Collector):

    name = "phishtank_urls"
    enabled_by_default = True

    URL = "https://data.phishtank.com/data/online-valid.csv"

    def collect(self) -> Iterable[IntelItem]:
        resp = self.http.cached_get(self.URL, "data/cache", ttl_seconds=1800,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
        if not resp.ok:
            self.log.warning("phishtank failed: %s status=%s", resp.error, resp.status)
            return []
        import csv
        import io
        out: list[IntelItem] = []
        reader = csv.DictReader(io.StringIO(resp.body))
        limit = int(self.cfg.get("limit", 2000))
        for row in reader:
            u = (row.get("url") or "").strip()
            if not u.startswith("http"):
                continue
            out.append(self.item("ioc_url", u,
                                 source_ref=row.get("phish_detail_url", ""),
                                 tlp="CLEAR", confidence=0.75,
                                 tags=["phishing", "phishtank", row.get("target", "") or "brand"],
                                 attributes={"verified": row.get("verified", ""),
                                             "submitted": row.get("submission_time", "")}))
            if len(out) >= limit:
                break
        return out


class EmergingCompromisedCollector(Collector):

    name = "emerging_compromised"
    enabled_by_default = True

    URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

    def collect(self) -> Iterable[IntelItem]:
        resp = self.http.cached_get(self.URL, "data/cache", ttl_seconds=3600,
                                    allow_robots_override=True)
        if not resp.ok:
            self.log.warning("emerging compromised failed: %s status=%s",
                             resp.error, resp.status)
            return []
        out: list[IntelItem] = []
        for line in resp.body.splitlines():
            ip = line.strip()
            if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ip):
                out.append(self.item("ioc_ipv4", ip, source_ref=self.URL,
                                     tlp="CLEAR", confidence=0.8,
                                     tags=["compromised-host", "emergingthreats"]))
        return out


class ThreatFoxCsvCollector(Collector):

    name = "threatfox_csv"
    enabled_by_default = True

    URL = "https://threatfox.abuse.ch/export/csv/recent/"

    def collect(self) -> Iterable[IntelItem]:
        resp = self.http.cached_get(self.URL, "data/cache", ttl_seconds=600,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
                                    allow_robots_override=True)
        if not resp.ok:
            self.log.warning("threatfox csv failed: %s status=%s", resp.error, resp.status)
            return []
        import csv
        import io
        lines = [ln for ln in resp.body.splitlines()
                 if not ln.startswith("#") and '"' in ln]
        header = ["first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type",
                  "fk_malware", "malware_alias", "malware_printable", "last_seen_utc",
                  "confidence_level", "is_compromised", "reference", "tags",
                  "anonymous", "reporter"]
        out: list[IntelItem] = []
        cat_map = {"ip:port": "ioc_ipv4", "domain": "ioc_domain", "url": "ioc_url"}
        for row in csv.reader(io.StringIO("\n".join(lines)), skipinitialspace=True):
            if len(row) < 4:
                continue
            rec = dict(zip(header, row))
            val = rec["ioc_value"].strip()
            cat = cat_map.get(rec["ioc_type"], "ioc_url")
            if cat == "ioc_ipv4" and ":" in val:
                val = val.split(":")[0]
            if not val:
                continue
            conf = 0.85
            try:
                conf = min(0.95, max(0.5, float(rec.get("confidence_level", "50")) / 100 + 0.4))
            except ValueError:
                pass
            out.append(self.item(cat, val, source_ref=rec.get("reference", ""),
                                 tlp="CLEAR", confidence=conf,
                                 tags=["threatfox", rec.get("malware_printable", "") or "unknown"],
                                 attributes={"threat_type": rec.get("threat_type", ""),
                                             "malware": rec.get("malware_printable", ""),
                                             "first_seen": rec.get("first_seen_utc", ""),
                                             "reported_by": rec.get("reporter", "")}))
        return out


    API = "https://threatfox-api.abuse.ch/v1/recent/"

    def collect(self) -> Iterable[IntelItem]:
        return []
        if not resp.ok:
            self.log.warning("threatfox api failed: %s status=%s", resp.error, resp.status)
            return []
        try:
            data = resp.json()
        except Exception:
            return []
        out: list[IntelItem] = []
        for e in (data.get("items") or [])[:500]:
            ioc = e.get("ioc", "")
            itype = e.get("ioc_type", "")
            cat = {"ip:port": "ioc_ipv4", "domain": "ioc_domain",
                   "url": "ioc_url", "uri": "ioc_url"}.get(itype, "ioc_url")
            val = ioc.split(":")[0] if cat == "ioc_ipv4" and ":" in ioc else ioc
            if not val:
                continue
            out.append(self.item(cat, val, source_ref=self.API, tlp="CLEAR",
                                 confidence=0.85,
                                 tags=["threatfox", e.get("malware", "") or "unknown-family"],
                                 attributes={"threat_type": e.get("threat_type", ""),
                                             "malware": e.get("malware", ""),
                                             "first_seen": e.get("first_seen_utc", ""),
                                             "reported_by": e.get("reported_by", "")}))
        return out


class ExploitDbCvesCollector(Collector):

    name = "exploitdb_cves"
    enabled_by_default = True

    URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

    def collect(self) -> Iterable[IntelItem]:
        resp = self.http.cached_get(self.URL, "data/cache", ttl_seconds=86400)
        if not resp.ok:
            self.log.warning("exploitdb csv failed: %s status=%s", resp.error, resp.status)
            return []
        seen: set[str] = set()
        out: list[IntelItem] = []
        for line in resp.body.splitlines()[1:]:
            for m in re.finditer(r"CVE-\d{4}-\d{4,7}", line):
                cve = m.group(0).upper()
                if cve in seen:
                    continue
                seen.add(cve)
                fields = next(csv.reader([line]))
                title = fields[3] if len(fields) > 3 else ""
                out.append(self.item("cve", cve, source_ref=self.URL,
                                     tags=["exploit-available", "exploitdb"],
                                     confidence=0.8,
                                     attributes={"example_exploit_title": title[:200]}))
        return out


class SslblFingerprintCollector(Collector):

    name = "sslbl_fingerprints"
    enabled_by_default = True

    URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"

    def collect(self) -> Iterable[IntelItem]:
        resp = self.http.cached_get(self.URL, "data/cache", ttl_seconds=3600,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
                                    allow_robots_override=True)
        if not resp.ok:
            self.log.warning("sslbl failed: %s status=%s", resp.error, resp.status)
            return []
        out: list[IntelItem] = []
        cap = int(self.cfg.get("max_items", 2000))
        for line in resp.body.splitlines():
            fp = line.strip().rstrip(",")
            if re.fullmatch(r"[a-fA-F0-9]{40}", fp):
                out.append(self.item("ioc_sha1", fp.lower(), source_ref=self.URL,
                                     tlp="CLEAR", confidence=0.85,
                                     tags=["malicious-ssl-cert", "sslbl"]))
                if len(out) >= cap:
                    break
        return out


class RansomwareLiveProfilesCollector(Collector):

    name = "ransomware_live_profiles"
    enabled_by_default = True

    URLS = ["https://raw.githubusercontent.com/PRISMAgroupransomwarelabs/Ransomware-Tracker/main/ransomware_groups_names.csv"]

    def collect(self) -> Iterable[IntelItem]:
        urls = self.cfg.get("urls") or self.URLS
        out: list[IntelItem] = []
        for url in urls:
            resp = self.http.cached_get(url, "data/cache", ttl_seconds=86400)
            if not resp.ok:
                self.log.warning("ransomware profiles %s failed: %s status=%s",
                                 url, resp.error, resp.status)
                continue
            reader = csv.DictReader(io.StringIO(resp.body))
            for row in reader:
                name = (row.get("Ransomware Group Name") or row.get("name")
                        or row.get("group") or "").strip()
                link = (row.get("URL") or row.get("site") or row.get("url") or "").strip()
                notes = (row.get("Notes") or "").strip()
                if not name:
                    continue
                out.append(self.item("threat_actor", name, source_ref=link or url,
                                     tlp="CLEAR", confidence=0.75,
                                     tags=["ransomware-group", "profile-watch"],
                                     attributes={"leak_site": link, "notes": notes[:300]}))
        return out


class HostsBlocklistCollector(Collector):

    name = "hosts_blocklists"
    enabled_by_default = True

    URLS = ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
    ADWARE_ONLY = {"0.0.0.0 adaware.badpeers.example.com"}

    def collect(self) -> Iterable[IntelItem]:
        cap = int(self.cfg.get("max_items", 5000))
        out: list[IntelItem] = []
        seen: set[str] = set()
        for url in self.cfg.get("urls") or self.URLS:
            resp = self.http.cached_get(url, "data/cache", ttl_seconds=86400)
            if not resp.ok:
                self.log.warning("hosts blocklist %s failed: %s status=%s",
                                 url, resp.error, resp.status)
                continue
            for line in resp.body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) != 2 or parts[0] not in ("0.0.0.0", "127.0.0.1"):
                    continue
                domain = parts[1].lower()
                if domain in seen or "." not in domain:
                    continue
                seen.add(domain)
                out.append(self.item("ioc_domain", domain, source_ref=url,
                                     tlp="CLEAR", confidence=0.6,
                                     tags=["blocklist", "crowd-sourced"]))
                if len(out) >= cap:
                    break
        return out


class OnionooRelayCollector(Collector):

    name = "tor_relays"
    enabled_by_default = True

    URL = "https://onionoo.torproject.org/details?type=relay&limit=250"

    def collect(self) -> Iterable[IntelItem]:
        resp = self.http.cached_get(self.cfg.get("url", self.URL), "data/cache",
                                    ttl_seconds=86400, allow_robots_override=True)
        if not resp.ok:
            self.log.warning("onionoo failed: %s status=%s", resp.error, resp.status)
            return []
        try:
            data = resp.json()
        except Exception:
            return []
        out: list[IntelItem] = []
        flags_only = bool(self.cfg.get("flagged_only", False))
        for r in data.get("relays") or []:
            flags = r.get("flags") or []
            if flags_only and not {"BadExit", "Exit"} & set(flags):
                continue
            ip = r.get("or_address") or r.get("address") or ""
            fingerprint = (r.get("fingerprint") or "").lower()
            if not ip:
                continue
            attrs = {"nickname": r.get("nickname", ""),
                     "country": r.get("country", ""),
                     "as": r.get("as", ""),
                     "flags": ",".join(flags),
                     "last_seen": r.get("last_seen", "")}
            out.append(self.item("ioc_ipv4", ip, source_ref=self.URL,
                                 tlp="CLEAR", confidence=0.5,
                                 tags=["tor-relay", "anonymization"],
                                 attributes=attrs))
            if fingerprint:
                out.append(self.item("entity_id", f"tor:{fingerprint}",
                                     source_ref=self.URL, tlp="CLEAR",
                                     confidence=0.5, tags=["tor-relay"],
                                     attributes={"ip": ip,
                                                 "nickname": r.get("nickname", "")}))
        return out

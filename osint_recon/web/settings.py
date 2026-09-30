from __future__ import annotations

import os
import stat
from pathlib import Path

ENV_PATH = Path(".env")

CRED_ENV_KEYS = [
    "GITHUB_TOKEN",
    "TG_API_ID",
    "TG_API_HASH",
    "DISCORD_BOT_TOKEN",
    "HIBP_API_KEY",
]

FORM_FIELDS = [
    ("github_token", "GITHUB_TOKEN"),
    ("tg_api_id", "TG_API_ID"),
    ("tg_api_hash", "TG_API_HASH"),
    ("discord_bot_token", "DISCORD_BOT_TOKEN"),
    ("hibp_api_key", "HIBP_API_KEY"),
]


def _split_list(raw: str) -> list[str]:
    parts = raw.replace(",", "\n").splitlines()
    return [p.strip() for p in parts if p.strip()]


def read_env_file(path: Path = ENV_PATH) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def write_env_file(values: dict[str, str], path: Path = ENV_PATH) -> None:
    merged = read_env_file(path)
    merged.update({k: v for k, v in values.items() if v})
    lines = [f"{k}={v}" for k, v in sorted(merged.items())]
    path.write_text("\n".join(lines) + "\n")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def apply_env_to_process(values: dict[str, str]) -> None:
    for k, v in values.items():
        if v:
            os.environ[k] = v


def cred_status() -> dict[str, bool]:
    saved = read_env_file()
    return {k: bool(saved.get(k) or os.getenv(k)) for k in CRED_ENV_KEYS}


def load_yaml(path: Path) -> dict:
    import yaml
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def save_yaml(data: dict, path: Path) -> None:
    import yaml
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))


def update_config(cfg_path: Path, form: dict[str, str]) -> dict[str, int]:
    cfg = load_yaml(cfg_path)
    sources = cfg.setdefault("sources", {})
    counts: dict[str, int] = {}

    def section(name: str) -> dict:
        return sources.setdefault(name, {})

    watch_terms = _split_list(form.get("watch_terms", ""))
    if watch_terms:
        cfg["watch_terms"] = watch_terms
        counts["watch_terms"] = len(watch_terms)

    github_repos = _split_list(form.get("github_secret_repos", ""))
    gh_queries = _split_list(form.get("github_search_queries", ""))
    s = section("github_secrets")
    s["enabled"] = True
    if github_repos:
        s["repos"] = github_repos
        counts["github_secret_repos"] = len(github_repos)
    if gh_queries:
        s["queries"] = gh_queries
        s["use_code_search"] = True
        counts["github_search_queries"] = len(gh_queries)

    tg_channels = _split_list(form.get("telegram_channels", ""))
    s = section("telegram")
    s["enabled"] = True
    if tg_channels:
        s["channels"] = tg_channels
        counts["telegram_channels"] = len(tg_channels)

    dc_channels = _split_list(form.get("discord_channels", ""))
    s = section("discord")
    s["enabled"] = True
    if dc_channels:
        ids = {}
        for token in dc_channels:
            label = token
            cid = token.split("/").pop().strip()
            ids[cid] = label
        s["channel_ids"] = ids
        counts["discord_channels"] = len(ids)

    hibp_domains = _split_list(form.get("hibp_domains", ""))
    s = section("hibp_domain")
    s["enabled"] = True
    if hibp_domains:
        s["domains"] = hibp_domains
        counts["hibp_domains"] = len(hibp_domains)

    forum_sites = _split_list(form.get("forum_sites", ""))
    s = section("forums")
    s["enabled"] = True
    if forum_sites:
        sites = []
        for u in forum_sites:
            host = u.replace("https://", "").replace("http://", "").strip("/")
            sites.append({"base_url": f"https://{host}", "search_path": "/search/"})
        s["sites"] = sites
        counts["forum_sites"] = len(sites)

    dump_urls = _split_list(form.get("dump_urls", ""))
    paste_terms = _split_list(form.get("paste_watch_terms", ""))
    s = section("paste_dumps")
    s["enabled"] = True
    if dump_urls:
        s["dump_urls"] = dump_urls
        counts["dump_urls"] = len(dump_urls)
    if paste_terms:
        s["watch_terms"] = paste_terms
        counts["paste_watch_terms"] = len(paste_terms)

    teaser_url = form.get("leak_teaser_url", "").strip()
    teaser_token = form.get("leak_teaser_token", "").strip()
    s = section("leak_teasers")
    if teaser_url:
        s["url"] = teaser_url
        s["enabled"] = True
        counts["leak_teaser_url"] = 1
    if teaser_token:
        s["token"] = teaser_token

    tw_channels = _split_list(form.get("telegram_web_channels", ""))
    tw_terms = _split_list(form.get("telegram_keywords", ""))
    s = section("telegram_web")
    s["enabled"] = True
    if tw_channels:
        s["channels"] = tw_channels
        counts["telegram_web_channels"] = len(tw_channels)
    if tw_terms:
        s["keywords"] = tw_terms
        counts["telegram_keywords"] = len(tw_terms)

    dc_invites = _split_list(form.get("discord_invite_codes", ""))
    s = section("discord_public")
    s["enabled"] = True
    if dc_invites:
        s["invite_codes"] = dc_invites
        counts["discord_invite_codes"] = len(dc_invites)

    cert_domains = _split_list(form.get("crtsh_domains", ""))
    s = section("crtsh_certs")
    s["enabled"] = True
    if cert_domains:
        s["domains"] = cert_domains
        counts["crtsh_domains"] = len(cert_domains)

    ransom_watch = _split_list(form.get("ransom_watchlist", ""))
    s = section("ransom_leaks")
    s["enabled"] = True
    if ransom_watch:
        s["watchlist"] = ransom_watch
        counts["ransom_watchlist"] = len(ransom_watch)

    mb_terms = _split_list(form.get("malwarebazaar_terms", ""))
    s = section("malwarebazaar_brand")
    s["enabled"] = True
    if mb_terms:
        s["search_terms"] = mb_terms
        counts["malwarebazaar_terms"] = len(mb_terms)

    doc_seeds = _split_list(form.get("doc_seed_urls", ""))
    s = section("doc_links")
    s["enabled"] = True
    if doc_seeds:
        s["seed_urls"] = doc_seeds
        counts["doc_seed_urls"] = len(doc_seeds)

    rentry_terms = _split_list(form.get("rentry_terms", ""))
    s = section("rentry_search")
    s["enabled"] = True
    if rentry_terms:
        s["watch_terms"] = rentry_terms
        counts["rentry_terms"] = len(rentry_terms)

    rss_feeds = _split_list(form.get("rss_feeds", ""))
    s = section("rss_reports")
    s["enabled"] = True
    if rss_feeds:
        feeds = {}
        for i, u in enumerate(rss_feeds):
            host = u.replace("https://", "").replace("http://", "").split("/")[0]
            feeds[host or f"feed{i}"] = u
        s["feeds"] = feeds
        counts["rss_feeds"] = len(feeds)

    stix_urls = _split_list(form.get("stix_urls", ""))
    s = section("stix_files")
    s["enabled"] = True
    if stix_urls:
        s["urls"] = stix_urls
        counts["stix_urls"] = len(stix_urls)

    text_urls = _split_list(form.get("text_feed_urls", ""))
    s = section("text_feeds")
    s["enabled"] = True
    if text_urls:
        feeds = {}
        for i, u in enumerate(text_urls):
            host = u.replace("https://", "").replace("http://", "").split("/")[0]
            feeds[f"{host}-{i}"] = u
        s["feeds"] = feeds
        counts["text_feed_urls"] = len(feeds)

    sec8k = form.get("sec_8k_enabled", "") == "on"
    s = section("sec_8k_item105")
    s["enabled"] = sec8k
    counts["sec_8k_item105"] = int(sec8k)

    save_yaml(cfg, cfg_path)
    return counts

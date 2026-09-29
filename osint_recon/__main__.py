from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pipeline import Pipeline, load_config, setup_logging


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="osint_recon",
        description="Automated multi-source OSINT/CTI gathering (public & "
                    "authorised sources only; secrets redacted at ingest).")
    ap.add_argument("--config", default="config/feeds.yaml",
                    help="YAML config (default: config/feeds.yaml)")
    ap.add_argument("--only", default="",
                    help="comma-separated collector names to run this time")
    ap.add_argument("--list-sources", action="store_true",
                    help="print available collectors and exit")
    ap.add_argument("--dry-run", action="store_true",
                    help="show which collectors would run, fetch nothing")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    setup_logging(args.verbose)

    from .pipeline import ALL_COLLECTOR_CLASSES
    if args.list_sources:
        for cls in ALL_COLLECTOR_CLASSES:
            print(f"{cls.name:24s} default_enabled={cls.enabled_by_default}")
        return 0

    cfg_path = Path(args.config)
    if cfg_path.exists():
        cfg = load_config(cfg_path)
    else:
        print(f"note: {cfg_path} not found -> using built-in defaults", file=sys.stderr)
        cfg = {}

    if args.only:
        cfg["_only"] = [s.strip() for s in args.only.split(",") if s.strip()]

    pipe = Pipeline(cfg)

    if args.dry_run:
        cols = pipe.build_collectors()
        print("collectors that WOULD run:")
        for c in cols:
            print(f"  - {c.name}")
        if not cols:
            print("  (none - check enabled flags in config)")
        return 0

    run_dir = pipe.run()
    print(f"\nrun complete -> {run_dir}")
    for f in ("items.jsonl", "iocs.csv", "summary.md"):
        p = run_dir / f
        if p.exists():
            print(f"  {p}  ({p.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
import subprocess
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

RUNS_DIR = Path("data/runs")
STATE_DIR = Path("data/state")


def _iter_items(run: str | None = None):
    if run:
        dirs = [RUNS_DIR / run]
    else:
        dirs = sorted(RUNS_DIR.iterdir(), reverse=True) if RUNS_DIR.exists() else []
    for d in dirs:
        jl = d / "items.jsonl"
        if not jl.exists():
            continue
        with jl.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield d.name, json.loads(line)
                except json.JSONDecodeError:
                    continue


def list_runs() -> list[dict]:
    out = []
    if not RUNS_DIR.exists():
        return out
    for d in sorted(RUNS_DIR.iterdir(), reverse=True):
        jl = d / "items.jsonl"
        n = 0
        cats: Counter = Counter()
        redacted = 0
        if jl.exists():
            with jl.open() as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        it = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    n += 1
                    cats[it.get("category", "?")] += 1
                    if it.get("redacted"):
                        redacted += 1
        out.append({
            "run": d.name,
            "items": n,
            "categories": len(cats),
            "redacted": redacted,
            "has_summary": (d / "summary.md").exists(),
        })
    return out


def stats(run: str | None = None) -> dict:
    by_cat: Counter = Counter()
    by_src: Counter = Counter()
    by_bucket: Counter = Counter()
    timeline: dict[str, Counter] = defaultdict(Counter)
    total = 0
    redacted = 0
    for run_name, it in _iter_items(run):
        total += 1
        cat = it.get("category", "?")
        src = it.get("source", "?").split(":")[0]
        bucket = cat.split("_")[0] if "_" in cat else cat
        by_cat[cat] += 1
        by_src[src] += 1
        by_bucket[bucket] += 1
        ts = (it.get("collected_at") or "")[:13]
        if ts:
            timeline[ts][bucket] += 1
        if it.get("redacted"):
            redacted += 1
    return {
        "total": total,
        "redacted": redacted,
        "by_category": by_cat.most_common(),
        "by_source": by_src.most_common(),
        "by_bucket": by_bucket.most_common(),
        "timeline": [{"hour": h, **dict(c)} for h, c in sorted(timeline.items())],
    }


def search_items(q: str = "", category: str = "", source: str = "",
                 run: str = "", limit: int = 200) -> list[dict]:
    ql = q.lower()
    results = []
    for run_name, it in _iter_items(run or None):
        if category and it.get("category") != category:
            continue
        if source and not it.get("source", "").startswith(source):
            continue
        if ql:
            hay = " ".join([
                str(it.get("value", "")),
                str(it.get("source", "")),
                " ".join(it.get("tags", [])),
                json.dumps(it.get("attributes", {}), default=str),
            ]).lower()
            if ql not in hay:
                continue
        it["_run"] = run_name
        results.append(it)
        if len(results) >= limit:
            break
    return results


class RunJob:
    def __init__(self, only: str = ""):
        self.only = only
        self.status = "queued"
        self.started = None
        self.finished = None
        self.output = []
        self.returncode = None
        self.thread = None

    def start(self):
        self.started = time.time()
        self.status = "running"
        self.thread = threading.Thread(target=self._exec, daemon=True)
        self.thread.start()

    def _exec(self):
        cmd = ["python3", "-m", "osint_recon", "-v"]
        if self.only:
            cmd += ["--only", self.only]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                self.output.append(line.rstrip())
            self.returncode = proc.wait()
            self.status = "done" if self.returncode == 0 else "failed"
        except Exception as exc:
            self.output.append(str(exc))
            self.status = "failed"
            self.returncode = -1
        self.finished = time.time()

    @classmethod
    def spawn(cls, target_fn) -> "RunJob":
        job = cls()
        job.started = time.time()
        job.status = "running"

        def _wrapped():
            try:
                target_fn(job)
            except Exception as exc:
                job.output.append(str(exc))
                job.status = "failed"
                job.returncode = -1
            finally:
                if job.status == "running":
                    job.status = "done"
                job.finished = time.time()

        job.thread = threading.Thread(target=_wrapped, daemon=True)
        job.thread.start()
        with _jobs_lock:
            _jobs[str(job.started)] = job
        return job

    def log(self, msg: str) -> None:
        self.output.append(msg)

    def finish(self, code: int) -> None:
        self.returncode = code
        self.status = "done" if code == 0 else "failed"


_jobs: dict[str, RunJob] = {}
_jobs_lock = threading.Lock()


def create_app(data_dir: Path | None = None) -> Flask:
    global RUNS_DIR, STATE_DIR
    if data_dir:
        RUNS_DIR = data_dir / "runs"
        STATE_DIR = data_dir / "state"
    app = Flask(__name__)

    def bucket_of(category: str) -> str:
        head = (category or "").split("_")[0].split(" ")[0]
        known = {"ioc", "leak", "leaked", "actor", "report", "threat", "chat",
                 "forum", "paste", "github", "doc", "ransom", "device",
                 "infected", "stealer", "secret"}
        return head if head in known else "github"

    app.jinja_env.globals["bucket_of"] = bucket_of

    @app.context_processor
    def inject_globals():
        return {
            "runs": list_runs(),
            "selected": request.view_args.get("run", "") if request.view_args else "",
        }

    @app.route("/")
    def home():
        runs = list_runs()
        latest = runs[0]["run"] if runs else ""
        st = stats(latest or None)
        recent = search_items(run=latest, limit=40) if latest else []
        return render_template("index.html", runs=runs, selected=latest,
                               stats=st, items=recent, active="events")

    @app.route("/events")
    @app.route("/events/<run>")
    def events(run: str = ""):
        runs = list_runs()
        if run and not any(r["run"] == run for r in runs):
            abort(404)
        st = stats(run or None)
        items = search_items(run=run, limit=200)
        return render_template("events.html", runs=runs, selected=run,
                               stats=st, items=items, active="events")

    @app.route("/item/<item_id>")
    def item_detail(item_id: str):
        found = None
        for run_name, it in _iter_items():
            if it.get("id") == item_id:
                it["_run"] = run_name
                found = it
                break
        if not found:
            abort(404)
        return render_template("item.html", item=found, active="events")

    @app.route("/sources")
    def sources():
        try:
            res = subprocess.run(["python3", "-m", "osint_recon", "--list-sources"],
                                 capture_output=True, text=True, timeout=60)
            lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
        except Exception:
            lines = []
        collectors = []
        for l in lines:
            parts = l.split()
            if not parts:
                continue
            collectors.append({
                "name": parts[0],
                "default_enabled": "default_enabled=True" in l,
            })
        st = stats()
        counts = dict(st["by_source"])
        for c in collectors:
            c["items"] = counts.get(c["name"], 0)
        return render_template("sources.html", collectors=collectors,
                               by_source=st["by_source"], active="sources")

    @app.route("/search")
    def search():
        q = request.args.get("q", "").strip()
        category = request.args.get("category", "").strip()
        source = request.args.get("source", "").strip()
        run = request.args.get("run", "").strip()
        items = search_items(q=q, category=category, source=source,
                             run=run, limit=300) if (q or category or source) else []
        st = stats()
        return render_template("search.html", q=q, category=category,
                               source=source, run=run, items=items,
                               categories=[c for c, _ in st["by_category"]],
                               sources_list=[s for s, _ in st["by_source"]],
                               active="search")

    @app.route("/api/stats")
    def api_stats():
        return jsonify(stats(request.args.get("run") or None))

    @app.route("/api/items")
    def api_items():
        return jsonify(search_items(
            q=request.args.get("q", ""),
            category=request.args.get("category", ""),
            source=request.args.get("source", ""),
            run=request.args.get("run", ""),
            limit=min(int(request.args.get("limit", 200)), 5000),
        ))

    @app.route("/api/runs")
    def api_runs():
        return jsonify(list_runs())

    @app.route("/api/trigger", methods=["POST"])
    def api_trigger():
        only = (request.get_json(silent=True) or {}).get("only", "")
        job = RunJob(only=only)
        job.start()
        key = str(job.started)
        with _jobs_lock:
            _jobs[key] = job
        return jsonify({"started": True, "job": key})

    @app.route("/api/jobs")
    def api_jobs():
        with _jobs_lock:
            return jsonify([{
                "status": j.status,
                "only": j.only,
                "returncode": j.returncode,
                "duration": (j.finished or time.time()) - (j.started or time.time()),
                "tail": j.output[-30:],
            } for j in _jobs.values()])

    return app


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="osint_recon.web")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args(argv)
    app = create_app()
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()

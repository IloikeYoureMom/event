#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
CONFIG="${CONFIG:-config/feeds.yaml}"
ONLY="${ONLY:-}"
MODE="${1:-serve}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found in PATH" >&2
    exit 1
fi

if [ ! -f "$CONFIG" ]; then
    echo "config file not found: $CONFIG" >&2
    exit 1
fi

if ! python3 -c "import flask, yaml, urllib3" >/dev/null 2>&1; then
    python3 -m pip install --quiet --disable-pip-version-check flask pyyaml urllib3
fi

case "$MODE" in
    serve)
        if [ -n "$ONLY" ]; then
            exec python3 -m osint_recon --config "$CONFIG" --serve --host "$HOST" --port "$PORT" --only "$ONLY"
        fi
        exec python3 -m osint_recon --config "$CONFIG" --serve --host "$HOST" --port "$PORT"
        ;;
    run)
        if [ -n "$ONLY" ]; then
            exec python3 -m osint_recon --config "$CONFIG" --only "$ONLY"
        fi
        exec python3 -m osint_recon --config "$CONFIG"
        ;;
    ui)
        exec python3 -m osint_recon.web --host "$HOST" --port "$PORT"
        ;;
    dry-run)
        exec python3 -m osint_recon --config "$CONFIG" --dry-run
        ;;
    sources)
        exec python3 -m osint_recon --list-sources
        ;;
    *)
        echo "usage: ./launch.sh [serve|run|ui|dry-run|sources]" >&2
        echo "env overrides: HOST PORT CONFIG ONLY" >&2
        exit 2
        ;;
esac

#!/usr/bin/env bash
# Track 02 full cycle — v1 → v2 → v3 in one command (~10 seconds, no cluster).
#
#   bash scripts/regression-cycle-demo.sh
#   bash scripts/regression-cycle-demo.sh --keep-history   # diff vs existing memory
#
# Brings FalkorDB up if it isn't listening, then hands over to
# scripts/regression_cycle_demo.py, which replays the committed snapshots:
# v1 (73 NEW) → accept the hero-chain risk → v2 (the fix: 68 RESOLVED)
# → v3 (the same admin grant re-added through another route: 1 REGRESSED).
#
# The snapshots themselves are committed; regenerate them from a live kind
# cluster with: python scripts/make_demo_snapshots.py
set -euo pipefail
cd "$(dirname "$0")/.." # backend/

COMPOSE_FILE="../docker-compose.yml"

_up() { (exec 3<>/dev/tcp/127.0.0.1/6380) 2>/dev/null; }

if ! _up; then
  echo "• FalkorDB not listening on :6380 — starting it via docker compose"
  docker compose -f "$COMPOSE_FILE" up -d falkordb >/dev/null
  for _ in $(seq 1 30); do
    _up && break
    sleep 1
  done
  _up || {
    echo "! FalkorDB did not come up; run: docker compose -f $COMPOSE_FILE up -d falkordb" >&2
    exit 2
  }
fi

PY=".venv/bin/python"
[ -x "$PY" ] || PY="python3"
exec "$PY" scripts/regression_cycle_demo.py "$@"

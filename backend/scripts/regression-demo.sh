#!/usr/bin/env bash
# Track 02 regression demo — reruns in ~30 seconds.
#
#   bash scripts/regression-demo.sh                 # live kind cluster
#   bash scripts/regression-demo.sh --keep-history   # diff vs existing memory
#   bash scripts/regression-demo.sh --keep-broken    # leave the fix applied
#
# Brings FalkorDB up if it isn't listening, then hands over to
# scripts/regression_demo.py (which does the collect → ingest → delete →
# collect → ingest dance and asserts at least one RESOLVED finding).
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
exec "$PY" scripts/regression_demo.py "$@"

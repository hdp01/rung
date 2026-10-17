#!/usr/bin/env bash
# One container, four processes: FalkorDB (in-memory), FastAPI, the Next.js
# standalone server, and nginx as the single public entrypoint.
#
# The deployment is stateless: FalkorDB keeps no save files and the backend
# re-seeds the demo graph from the bundled snapshot on every boot.
set -euo pipefail

log() { echo "[entrypoint] $*"; }

# --- bake the public API origin into the frontend bundle --------------------
# The frontend was built carrying the `__RUNG_API_ORIGIN__` placeholder in its
# client bundle.  PUBLIC_API_URL (e.g. https://rung-track02.fly.dev, or a
# tunnel URL) is what the browser should call — substitute it now, so the same
# image works on any host without a rebuild.
if [ -n "${PUBLIC_API_URL:-}" ]; then
    origin="${PUBLIC_API_URL%/}"
    files=$(grep -rl "__RUNG_API_ORIGIN__" /srv/frontend 2>/dev/null || true)
    if [ -n "$files" ]; then
        echo "$files" | xargs -r sed -i "s|__RUNG_API_ORIGIN__|${origin}|g"
        log "frontend bundle patched for API origin ${origin}"
    else
        log "warning: API-origin placeholder not found in the frontend bundle"
    fi
fi

# --- FalkorDB ---------------------------------------------------------------
redis-server \
    --loadmodule /var/lib/falkordb/bin/falkordb.so \
    --port 6379 \
    --dir /tmp \
    --save '' \
    --appendonly no &
FALKORDB_PID=$!

for _ in $(seq 1 100); do
    redis-cli -p 6379 ping >/dev/null 2>&1 && break
    sleep 0.2
done
if ! redis-cli -p 6379 ping >/dev/null 2>&1; then
    log "FalkorDB did not start"
    exit 1
fi
log "FalkorDB ready on :6379"

# --- backend ----------------------------------------------------------------
cd /app
uvicorn app.main:app --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

for _ in $(seq 1 200); do
    curl -sf http://127.0.0.1:8000/health 2>/dev/null | grep -q '"falkordb":"connected"' && break
    sleep 0.3
done
if ! curl -sf http://127.0.0.1:8000/health 2>/dev/null | grep -q '"falkordb":"connected"'; then
    log "backend did not reach FalkorDB"
    exit 1
fi
log "backend ready on :8000"

# --- frontend ---------------------------------------------------------------
cd /srv/frontend
PORT=3000 HOSTNAME=127.0.0.1 node server.js &
FRONTEND_PID=$!

for _ in $(seq 1 100); do
    curl -sf http://127.0.0.1:3000/ >/dev/null && break
    sleep 0.3
done
curl -sf http://127.0.0.1:3000/ >/dev/null || log "warning: frontend slow to answer; nginx will 502 until it does"
log "frontend on :3000"

# --- nginx (public) ---------------------------------------------------------
term() {
    log "shutting down"
    kill -TERM "$NGINX_PID" "$FRONTEND_PID" "$BACKEND_PID" "$FALKORDB_PID" 2>/dev/null || true
}

NGINX_PID=""
trap term TERM INT
nginx -g 'daemon off;' &
NGINX_PID=$!
log "public entrypoint on :8080"

# If any process dies the machine is unhealthy — stop everything and let Fly
# restart the machine.
wait -n "$FALKORDB_PID" "$BACKEND_PID" "$FRONTEND_PID" "$NGINX_PID" || true
term
wait || true
exit 1

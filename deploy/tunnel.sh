#!/usr/bin/env bash
# Expose the deploy image at a public Cloudflare quick-tunnel URL — no
# account, no token.  Usage:
#
#   deploy/tunnel.sh              # reuse the built image
#   deploy/tunnel.sh --rebuild    # force a fresh docker build first
#
# The script starts the tunnel, reads its public URL, then starts the
# container with that URL baked in via PUBLIC_API_URL (the entrypoint
# substitutes it into the frontend bundle at boot).  Re-running the script
# picks up a new URL automatically.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

IMAGE=${IMAGE:-rung-deploy}
PORT=${PORT:-9080}
BIN_DIR=${HOME}/.local/share/rung
CLOUDFLARED="$BIN_DIR/cloudflared"
LOG="$BIN_DIR/tunnel.log"
ORIGIN="http://127.0.0.1:${PORT}"

mkdir -p "$BIN_DIR"

# 1. cloudflared binary (static, no install needed)
if [ ! -x "$CLOUDFLARED" ]; then
    echo "[tunnel] downloading cloudflared ..."
    curl -sL -o "$CLOUDFLARED" \
        https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
    chmod +x "$CLOUDFLARED"
fi

# 2. image
if [ "${1:-}" = "--rebuild" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[tunnel] building image $IMAGE ..."
    docker build -f deploy/fly/Dockerfile -t "$IMAGE" .
fi

# 3. (re)start the tunnel
pkill -f "cloudflared tunnel --url ${ORIGIN}" 2>/dev/null || true
sleep 0.3
: > "$LOG"
nohup "$CLOUDFLARED" tunnel --url "$ORIGIN" --no-autoupdate \
    >"$LOG" 2>&1 &
disown || true

URL=""
for _ in $(seq 1 60); do
    URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$LOG" 2>/dev/null | head -1 || true)
    [ -n "$URL" ] && break
    sleep 0.5
done
if [ -z "$URL" ]; then
    echo "[tunnel] no URL yet — see $LOG"
    exit 1
fi
echo "[tunnel] public URL: $URL"

# 4. (re)start the container with the URL baked at boot.
#    6389 is exposed on localhost only: it gives the regression demo scripts a
#    FalkorDB they can drive, so the PUBLIC UI can be flipped to the REGRESSED
#    moment live:
#      FALKORDB_HOST=127.0.0.1 FALKORDB_PORT=6389 \
#        backend/.venv/bin/python backend/scripts/regression_cycle_demo.py \
#        --api http://127.0.0.1:9080
#    Re-run this script (fresh container + re-seed) to reset to the v1 demo state.
KEY=""
[ -f "$ROOT/.env" ] && KEY=$(grep -m1 '^BEDROCK_API_KEY=' "$ROOT/.env" 2>/dev/null | cut -d= -f2- || true)
docker rm -f rung-deploy >/dev/null 2>&1 || true
docker run -d --name rung-deploy --restart unless-stopped \
    -p "127.0.0.1:${PORT}:8080" \
    -p "127.0.0.1:6389:6379" \
    -e "PUBLIC_API_URL=${URL}" \
    -e "BEDROCK_API_KEY=${KEY}" \
    -e "BEDROCK_MODEL_ID=${BEDROCK_MODEL_ID:-amazon.nova-pro-v1:0}" \
    -e "BEDROCK_REGION=${BEDROCK_REGION:-us-east-1}" \
    "$IMAGE" >/dev/null
echo "[tunnel] container 'rung-deploy' up on 127.0.0.1:${PORT}"

# 5. verify through the public URL
for _ in $(seq 1 90); do
    curl -sf "${URL}/health" >/dev/null 2>&1 && break
    sleep 1
done
echo "[tunnel] ${URL}/health -> $(curl -s "${URL}/health" || echo 'not up yet')"
echo "[tunnel] ${URL}/compare -> $(curl -s "${URL}/compare?tenant=kind-graphhacks" || echo 'not up yet')"
echo "$URL" > "$BIN_DIR/tunnel-url.txt"
echo "[tunnel] URL saved to $BIN_DIR/tunnel-url.txt"

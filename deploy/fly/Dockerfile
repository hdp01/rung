# syntax=docker/dockerfile:1
# One Fly machine holding the whole demo: FalkorDB, FastAPI, Next.js, and
# nginx as the single public entrypoint (see deploy/fly/README.md).
#
# The frontend bakes its API base at build time; instead of hard-coding an
# origin, the bundle carries the placeholder `__RUNG_API_ORIGIN__` and the
# entrypoint substitutes the public origin at start-up from the
# PUBLIC_API_URL env var (so the same image works on Fly, a tunnel, or
# anywhere — no rebuild when the URL changes).

# ---- frontend: Next.js standalone build ------------------------------------
# node:22-slim (Debian) so the node binary can also power the runtime stage.
FROM node:22-slim AS frontend
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
ARG NEXT_PUBLIC_API_URL=__RUNG_API_ORIGIN__
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
RUN npm run build

# ---- runtime: FalkorDB's own Debian base + python + node + nginx -----------
# Basing on falkordb/falkordb keeps redis-server and the graph module at
# exactly the paths their image uses (`/usr/local/bin/redis-server`,
# `/var/lib/falkordb/bin/falkordb.so`).
FROM falkordb/falkordb:v4.22.1

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# The falkordb base image prunes debconf's files (with dpkg state intact)
# and ships no perl — and debconf's frontend is a perl script.  Restore
# both before anything that runs debconf (nginx, iproute2).
RUN apt-get update \
 && apt-get install -y --no-install-recommends perl \
 && apt-get install -y --no-install-recommends --reinstall debconf \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libstdc++6 \
        nginx \
        python3 \
        python3-venv \
 && rm -rf /var/lib/apt/lists/*

# Node runtime for `next start`'s standalone server, same Debian line.
COPY --from=frontend /usr/local/bin/node /usr/local/bin/node
RUN node --version

# Backend: venv + requirements + code, same layout as backend/Dockerfile.
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/rung /app/rung
COPY backend/app /app/app
COPY backend/data /app/data
ENV PYTHONPATH=/app:/app/rung/src

# Frontend runtime files (standalone server + static assets + public/).
COPY --from=frontend /app/.next/standalone /srv/frontend
COPY --from=frontend /app/.next/static /srv/frontend/.next/static
COPY --from=frontend /app/public /srv/frontend/public

# nginx config + the process supervisor.
COPY deploy/fly/nginx.conf /etc/nginx/nginx.conf
COPY deploy/fly/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Inside this image FalkorDB always lives at 127.0.0.1:6379 and the demo
# snapshot is always at /app/data/demo-snapshot.json — make that the default
# so a bare `docker run` works.  (fly.toml/tunnel.sh simply restate this.)
ENV FALKORDB_HOST=127.0.0.1 \
    FALKORDB_PORT=6379 \
    FALKORDB_GRAPH=rung:kind-graphhacks \
    RUNG_SEED_SNAPSHOT=/app/data/demo-snapshot.json

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

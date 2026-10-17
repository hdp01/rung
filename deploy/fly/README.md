# Deploying Rung (one container, any host)

One machine runs the whole demo: **FalkorDB + FastAPI + Next.js + nginx** in a
single container (`Dockerfile`), with nginx on `:8080` as the only public
entrypoint. API paths (`/findings`, `/compare`, `/ask`, …) are proxied to the
backend; everything else is the frontend — same host, one origin.

The image is **origin-agnostic**: the frontend bundle carries the
`__RUNG_API_ORIGIN__` placeholder, and the entrypoint substitutes the public
origin from the `PUBLIC_API_URL` env var at start-up. Point it at a Fly URL, a
tunnel URL, or anything else — no rebuild when the URL changes.

The deployment is **stateless**: FalkorDB keeps no save files and the backend
re-seeds the demo graph from `backend/data/demo-snapshot.json` on every boot.

## Fly.io runbook

```bash
# 1. tooling + account (once)
curl -L https://fly.io/install.sh | sh
export FLYCTL_INSTALL="$HOME/.fly"
export PATH="$FLYCTL_INSTALL/bin:$PATH"
fly auth login                      # or: FLY_API_TOKEN=...

# 2. create the app (name must be globally unique; edit fly.toml if taken)
fly apps create rung-track02

# 3. secrets — the model key lives only here, and the demo records on Nova Pro
fly secrets set --app rung-track02 \
    BEDROCK_API_KEY="$(grep -m1 '^BEDROCK_API_KEY=' .env | cut -d= -f2-)" \
    BEDROCK_MODEL_ID="amazon.nova-pro-v1:0"

# 4. deploy (from the repo root — the image is origin-agnostic)
fly deploy

# 5. verify
curl -s https://rung-track02.fly.dev/health
# -> {"status":"ok","falkordb":"connected","graph":"rung:kind-graphhacks"}
curl -s 'https://rung-track02.fly.dev/compare?tenant=kind-graphhacks'
# -> naive_reachable 16 / rung_reachable 6 / tokens 1472/16  (the thesis)
open https://rung-track02.fly.dev/        # the UI, same host
```

## The same image without any account: `deploy/tunnel.sh`

When no PaaS credentials are available, `deploy/tunnel.sh` builds the image
(or reuses it), runs it on `:9080`, and exposes it through a Cloudflare
**quick tunnel** — a public `https://<words>.trycloudflare.com` URL with no
account and no token. The script bakes the tunnel URL into the container at
start-up via `PUBLIC_API_URL`. Caveats: the URL is random per run (the script
prints it every time) and lives only while this machine and the tunnel
process stay up — perfect for a demo/recording window, not for a permanent
deployment.

## Notes

* `fly deploy` uses `fly.toml` at the repo root; the build context is the repo
  (`.dockerignore` keeps `node_modules`, `.venv`, `.env` and friends out).
* `PUBLIC_API_URL` is read at container start (`deploy/fly/entrypoint.sh`);
  it defaults to the placeholder with a warning, so a browser run needs it
  set.  fly.toml provides it for Fly; `deploy/tunnel.sh` provides it for the
  tunnel.
* `BEDROCK_MODEL_ID` is a secret on purpose: the deploy defaults are fine, but
  the recorded demo runs `amazon.nova-pro-v1:0`.
* One `shared-cpu-1x`/1 GB machine is comfortable for the demo; the graph is
  tiny.  `auto_stop_machines = false` keeps FalkorDB warm.
* To iterate locally on the same image:
  ```bash
  docker build -f deploy/fly/Dockerfile -t rung-deploy .
  docker run --rm -p 9080:8080 -e PUBLIC_API_URL=http://127.0.0.1:9080 rung-deploy
  ```

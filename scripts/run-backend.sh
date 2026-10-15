#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

docker compose up -d --build backend

echo
echo "Backend is starting."
echo "  API:    http://localhost:8000"
echo "  Health: http://localhost:8000/health"
echo "  Stats:  http://localhost:8000/stats"
echo
echo "Logs: docker compose logs -f backend"

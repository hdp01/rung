#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

docker compose up -d --build frontend

echo
echo "Frontend is starting."
echo "  App:    http://localhost:3000"
echo
echo "If the backend is not running, start it first:"
echo "  ./scripts/run-backend.sh"
echo
echo "Logs: docker compose logs -f frontend"

.PHONY: up down logs seed test lint cluster collect
up:      ; cd .. && docker compose up --build -d && echo "ui on http://localhost:3000"
down:    ; cd .. && docker compose down
logs:    ; cd .. && docker compose logs -f backend
test:    ; uv run pytest -q
lint:    ; uv run ruff check app rung tests
cluster: ; ./scripts/bootstrap-cluster.sh
collect: ; uv run rung collect --context kind-graphhacks -o data/demo-snapshot.json

.PHONY: up down logs seed test lint cluster collect
up:      ; docker compose up --build -d && echo "http://localhost:8090"
down:    ; docker compose down
logs:    ; docker compose logs -f app
test:    ; uv run pytest -q
lint:    ; uv run ruff check src tests
cluster: ; ../graphhacks-prep/bootstrap.sh
collect: ; uv run rung collect --context kind-graphhacks -o data/demo-snapshot.json

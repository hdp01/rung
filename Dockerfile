FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml ./
RUN uv pip install --system --no-cache -r pyproject.toml
COPY src/ ./src/
COPY web/ ./web/
COPY data/ ./data/
RUN uv pip install --system --no-cache -e . --no-deps
EXPOSE 8080
CMD ["uvicorn", "rung.api:app", "--host", "0.0.0.0", "--port", "8080"]

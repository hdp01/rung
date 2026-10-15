"""Rung backend API — serves graph stats, FalkorDB health, and ingestion."""
import json
import os
import tempfile

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from rung.ingest import _graph, ingest

app = FastAPI(title="Rung API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _falkordb_ok() -> bool:
    try:
        g = _graph()
        g.query("RETURN 1")
        return True
    except Exception:
        return False


def _seed_path() -> str | None:
    candidates = [
        os.getenv("RUNG_SEED_SNAPSHOT"),
        "data/demo-snapshot.json",
        "/app/data/demo-snapshot.json",
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


@app.on_event("startup")
def seed_graph() -> None:
    path = _seed_path()
    if path is None:
        return
    try:
        ingest(path, stats=False)
    except Exception:  # noqa: BLE001
        # Seeding failure must not take down the API.
        pass


@app.get("/health")
def health():
    return {
        "status": "ok",
        "falkordb": "connected" if _falkordb_ok() else "disconnected",
        "graph": os.getenv("FALKORDB_GRAPH", "rung:kind-graphhacks"),
    }


@app.get("/stats")
def stats():
    try:
        g = _graph()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    from rung.ingest import _counts

    return _counts(g)


@app.post("/ingest")
async def ingest_snapshot(file: UploadFile = File(...)):
    try:
        content = await file.read()
        snapshot = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON: {exc}") from exc

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        json.dump(snapshot, tmp)
        path = tmp.name
    try:
        result = ingest(path, stats=False)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return {"status": "ingested", "counts": result}

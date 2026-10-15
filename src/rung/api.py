"""Scaffolding only. The real API is written during the event window (15-18 Oct).

Exists now so the deployment pipeline can be proven end to end beforehand.
"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

WEB = Path(__file__).resolve().parents[2] / "web"

app = FastAPI(title="Rung")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB / "index.html")


app.mount("/static", StaticFiles(directory=WEB), name="static")

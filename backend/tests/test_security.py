"""Security invariant tests — data hygiene and injection defences.

These tests prove the security story is real, not aspirational:
- No committed snapshot leaks Secret data fields (redaction invariant)
- The agent SYSTEM prompt instructs entity names to be treated as untrusted
- Stale-snapshot detection is wired (meta.collected_at present in snapshots)
- ingest() rejects snapshots older than 7 days unless allow_stale=True
"""
import json
import os
from datetime import UTC
from pathlib import Path

import pytest

from rung import agent
from rung.ingest import ingest

_DATA_DIR = Path(__file__).parent.parent / "data"
_DATASET_DIR = Path(__file__).parent.parent.parent / "dataset"


def _all_snapshots():
    paths = []
    for directory in (_DATA_DIR, _DATASET_DIR):
        if directory.exists():
            paths.extend(directory.rglob("*.json"))
    return paths


# ---------------------------------------------------------------------------
# Redaction invariant — Secret .data must never be committed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("snap_path", _all_snapshots())
def test_no_snapshot_leaks_secret_data(snap_path):
    """Every snapshot JSON must have empty or absent Secret data fields.

    rung collect redacts Secret .data at collection time. This test proves
    the invariant holds across every committed snapshot — a regression here
    means actual cluster credentials ended up in git.
    """
    snap = json.loads(snap_path.read_text())
    for sec in snap.get("secrets", []):
        assert "data" not in sec, (
            f"{snap_path}: Secret '{sec.get('name')}' has a 'data' field — "
            "redaction invariant violated"
        )


# ---------------------------------------------------------------------------
# Prompt-injection defence
# ---------------------------------------------------------------------------

def test_system_prompt_treats_entity_names_as_untrusted():
    """SYSTEM prompt must warn the model that entity names are untrusted data."""
    assert "untrusted" in agent.SYSTEM.lower(), (
        "SYSTEM prompt must include an instruction that entity names from the "
        "graph are untrusted strings — add the injection-guard clause"
    )


# ---------------------------------------------------------------------------
# Snapshot provenance — collected_at present
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("snap_path", _all_snapshots())
def test_snapshot_has_collected_at(snap_path):
    """Every real snapshot must carry a meta.collected_at timestamp.

    Without it, there's no way to detect a stale snapshot being re-submitted,
    which could cause the detector to report 'no new findings' misleadingly.
    Empty test fixtures (no top-level keys) are skipped.
    """
    snap = json.loads(snap_path.read_text())
    if not snap:
        pytest.skip("empty fixture — not a real cluster snapshot")
    # Only enforce on snapshots that look like real cluster data
    if "pods" not in snap and "namespaces" not in snap:
        pytest.skip("no pods/namespaces key — not a cluster snapshot")
    meta = snap.get("meta") or {}
    assert meta.get("collected_at"), (
        f"{snap_path}: missing meta.collected_at — snapshot provenance is broken"
    )


# ---------------------------------------------------------------------------
# Stale-snapshot guard — ingest() must reject old snapshots
# ---------------------------------------------------------------------------

def _write_snap(path, collected_at):
    snap = {
        "meta": {"collected_at": collected_at, "context": "test"},
        "namespaces": [], "nodes": [], "serviceaccounts": [],
        "secrets": [], "pods": [], "roles": [], "bindings": [],
    }
    path.write_text(json.dumps(snap))


def test_ingest_rejects_stale_snapshot(tmp_path, monkeypatch):
    monkeypatch.setenv("FALKORDB_HOST", "localhost")
    monkeypatch.setenv("FALKORDB_PORT", "6380")
    snap = tmp_path / "old.json"
    _write_snap(snap, "2025-01-01T00:00:00Z")  # clearly > 7 days old
    with pytest.raises(ValueError, match="days old"):
        ingest(str(snap))


def test_ingest_allows_stale_with_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("FALKORDB_HOST", "localhost")
    monkeypatch.setenv("FALKORDB_PORT", "6380")
    monkeypatch.setenv("FALKORDB_GRAPH", f"rung:stale-test-{os.getpid()}")
    snap = tmp_path / "old.json"
    _write_snap(snap, "2025-01-01T00:00:00Z")
    # Must not raise when allow_stale=True
    ingest(str(snap), allow_stale=True)


def test_ingest_accepts_fresh_snapshot(tmp_path, monkeypatch):
    from datetime import datetime
    monkeypatch.setenv("FALKORDB_HOST", "localhost")
    monkeypatch.setenv("FALKORDB_PORT", "6380")
    monkeypatch.setenv("FALKORDB_GRAPH", f"rung:fresh-test-{os.getpid()}")
    snap = tmp_path / "fresh.json"
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_snap(snap, now)
    ingest(str(snap))  # must not raise

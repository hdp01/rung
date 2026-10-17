"""Eval harness for Rung — runs questions.jsonl against the graph.

Usage:
    uv run python eval/run_eval.py [--snapshot PATH] [--tenant TENANT]

The harness:
1. Ingests the snapshot into a fresh temporary graph (rung:eval-run by default)
2. Runs each question's tool call and checks the result
3. Prints a pass/fail table; exits 0 when >= 9/10 pass, else 1.

Environment overrides:
  FALKORDB_HOST  — default localhost
  FALKORDB_PORT  — default 6380
  RUNG_EVAL_SNAPSHOT — path to snapshot JSON (default: data/demo-snapshot.json)
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from pathlib import Path

# Make `rung` importable from the backend root.
sys.path.insert(0, str(Path(__file__).parent.parent))

QUESTIONS_FILE = Path(__file__).parent / "questions.jsonl"
SNAPSHOT_DEFAULT = Path(__file__).parent.parent / "data" / "demo-snapshot.json"
PASS_THRESHOLD = 9


def _load_questions(path: Path) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _check_result(result: dict, checks: list[dict]) -> tuple[bool, str]:
    for check in checks:
        field = check["field"]
        op = check["op"]
        expected = check.get("value")
        actual = result.get(field)
        if op == "eq":
            if actual != expected:
                return False, f"{field!r}={actual!r}, want {expected!r}"
        elif op == "exists":
            if field not in result:
                return False, f"field {field!r} absent"
        elif op == "contains":
            if actual is None or expected not in actual:
                return False, f"{expected!r} not in {field!r} (got {actual!r})"
        elif op == "min_len":
            length = len(actual) if actual else 0
            if length < expected:
                return False, f"len({field!r})={length} < {expected}"
        elif op == "gte":
            if actual is None or actual < expected:
                return False, f"{field!r}={actual!r} < {expected}"
        else:
            return False, f"unknown op {op!r}"
    return True, "ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--snapshot", default=os.getenv("RUNG_EVAL_SNAPSHOT", str(SNAPSHOT_DEFAULT)))
    parser.add_argument("--tenant", default="eval-run")
    args = parser.parse_args(argv)

    snapshot_path = args.snapshot
    graph_name = f"rung:{args.tenant}"

    os.environ.setdefault("FALKORDB_HOST", "localhost")
    os.environ.setdefault("FALKORDB_PORT", "6380")
    os.environ["FALKORDB_GRAPH"] = graph_name

    from falkordb import FalkorDB

    from rung import agent
    from rung.ingest import ingest

    host = os.environ["FALKORDB_HOST"]
    port = int(os.environ["FALKORDB_PORT"])
    r = FalkorDB(host=host, port=port)

    # Fresh graph for a reproducible run.
    with contextlib.suppress(Exception):
        r.select_graph(graph_name).delete()

    print(f"Ingesting {snapshot_path} → {graph_name} ...")
    ingest(snapshot_path, allow_stale=True)
    g = r.select_graph(graph_name)

    questions = _load_questions(QUESTIONS_FILE)
    results: list[tuple[str, str, bool, str]] = []

    print(f"\nRunning {len(questions)} questions:\n")
    for q in questions:
        qid = q["id"]
        desc = q["desc"]
        tool = q["tool"]
        tool_args = q.get("args", {})
        checks = q.get("checks", [])

        result = agent._run_tool(tool, tool_args, g, snapshot_path)
        passed, reason = _check_result(result, checks)
        results.append((qid, desc, passed, reason))

        status = "PASS" if passed else "FAIL"
        short = desc[:65]
        print(f"  {status}  {qid}  {short}")
        if not passed:
            print(f"         reason : {reason}")
            print(f"         result : {json.dumps(result, default=str)[:200]}")

    passed_count = sum(1 for *_, p, _ in results if p)
    total = len(results)
    print(f"\n{'=' * 60}")
    print(f"Result: {passed_count}/{total} passed  (threshold: {PASS_THRESHOLD}/{total})")
    if passed_count >= PASS_THRESHOLD:
        print("EVAL PASSED ✓")
    else:
        print(f"EVAL FAILED — {PASS_THRESHOLD - passed_count} more question(s) must pass")

    # Clean up the eval graph.
    with contextlib.suppress(Exception):
        r.select_graph(graph_name).delete()

    return 0 if passed_count >= PASS_THRESHOLD else 1


if __name__ == "__main__":
    sys.exit(main())

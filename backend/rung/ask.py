"""Answering questions about the graph — the `/ask` endpoint.

This is a stand-in for Harsh's agent. It routes a natural-language question
to the plain functions in `graph`, `paths` and `sim`, and answers from what
they found. Everything except the routing itself is plain logic, so Harsh
can replace just this module when the real agent is wired up.

The endpoint (`app.main`) consumes `events` and streams the result as Server
Sent Events: one `data: {...}` line per event, exactly as the frontend's chat
panel expects (`tool` while the agent works, `token` for the answer as it is
typed, `path` to light up a chain, and `final` when the answer is complete).
"""
import json
import re

from . import paths as paths_logic

# Words that route a question to the path explorer.
_PATH_WORDS = ("path", "chain", "reach", "escalate")
# Words that route a question to the findings list.
_FINDINGS_WORDS = ("finding", "misconfig", "issue", "risk")


def build_answer(question, context):
    """The final answer: {answer, citations, status, finding}.

    `context` carries whatever the routing needs (`reaching_admin`,
    `findings`, `summary`); the answer itself is plain text.
    """
    q = (question or "").lower()

    if any(word in q for word in _PATH_WORDS):
        reaching = context["reaching_admin"]
        return {
            "answer": _paths_answer(reaching),
            "citations": [],
            "status": None,
            "finding": None,
        }
    if any(word in q for word in _FINDINGS_WORDS):
        tracked = context["findings"]
        return {
            "answer": (
                f"{len(tracked)} tracked route(s) are reported for this tenant."
            ),
            "citations": [],
            "status": None,
            "finding": None,
        }
    return {
        "answer": (
            "I can explain escalation paths, list what reaches cluster-admin, "
            "describe findings, and compare snapshots. Ask about any of those."
        ),
        "citations": [],
        "status": None,
        "finding": None,
    }


def events(question, context):
    """Yield the SSE events for this question, as plain dicts.

    The frontend appends every `token` to the assistant's message and shows
    the `final` event; `path` lights up the chain on the graph.
    """
    routing = _route(question)

    if routing == "paths":
        yield {"type": "tool", "name": "paths"}
        for entry in context["reaching_admin"]:
            yield {"type": "path", "steps": _path_steps(entry["paths"])}
    elif routing == "findings":
        yield {"type": "tool", "name": "findings"}
    else:
        yield {"type": "tool", "name": "summary"}

    final = build_answer(question, context)
    for chunk in _tokenize(final["answer"]):
        yield {"type": "token", "text": chunk}
    yield {
        "type": "final",
        "answer": final["answer"],
        "citations": final["citations"],
        "status": final["status"],
        "finding": final["finding"],
    }


def _route(question):
    q = (question or "").lower()
    if any(word in q for word in _PATH_WORDS):
        return "paths"
    if any(word in q for word in _FINDINGS_WORDS):
        return "findings"
    return "summary"


def _paths_answer(reaching_admin):
    """A short textual answer pointing at the paths just enumerated."""
    if not reaching_admin:
        return "No identity in this tenant reaches cluster-admin."
    identities = ", ".join(entry["identity"] for entry in reaching_admin)
    return f"{len(reaching_admin)} identity(ies) can escalate, e.g. {identities}."


def _path_steps(paths):
    """Convert a list of path views into the {from, edge, to} steps the UI shows."""
    steps = []
    for path in paths:
        for edge in path["edges"]:
            steps.append(
                {
                    "from": edge["from"],
                    "edge": edge["edge"],
                    "to": edge["to"],
                    "attack_path": edge["attack_path"],
                }
            )
    return steps


def _tokenize(text):
    """Split an answer into small, streamable chunks."""
    return [chunk for chunk in re.findall(r"\S+\s*", text) if chunk]

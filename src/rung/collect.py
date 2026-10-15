"""`rung collect` — read a cluster (read-only) into the snapshot.json contract.

Implement per HANDOFF.md, Task 1. Write the exact JSON shape documented there;
it is the only interface to the ingester. Never capture Secret .data.
"""


def collect(context: str, out: str) -> None:
    raise NotImplementedError("see HANDOFF.md, Task 1")

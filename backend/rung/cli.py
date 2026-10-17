"""Rung command-line entry point.

Subcommands and their contracts are specified in HANDOFF.md.
"""
import argparse


def main() -> None:
    p = argparse.ArgumentParser(prog="rung", description="K8s attack-path graph agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="read a cluster into snapshot.json")
    c.add_argument("--context", required=True, help="kubeconfig context")
    c.add_argument("-o", "--out", default="data/snapshot.json")

    i = sub.add_parser("ingest", help="build the graph in FalkorDB from a snapshot")
    i.add_argument("snapshot", help="path to snapshot.json")
    i.add_argument("--stats", action="store_true", help="print node/edge counts")

    f = sub.add_parser("findings", help="print the regression detector's tracked routes")
    f.add_argument("--limit", type=int, default=20, help="how many routes to print")

    sub.add_parser("snapshots", help="print the ingested snapshot history")

    args = p.parse_args()
    if args.cmd == "collect":
        from rung.collect import collect
        collect(context=args.context, out=args.out)
    elif args.cmd == "ingest":
        from rung.ingest import ingest
        ingest(snapshot_path=args.snapshot, stats=args.stats)
    elif args.cmd == "findings":
        from rung import graph as graph_logic
        from rung import paths as paths_logic

        for finding in paths_logic.findings(graph_logic.connect())[: args.limit]:
            print(
                f"{finding['status']:<9} {finding['route']}  ->  {finding['target']}"
            )
    elif args.cmd == "snapshots":
        from rung import findings as findings_logic
        from rung import graph as graph_logic

        for snap in findings_logic.snapshot_history(graph_logic.connect()):
            print(
                f"{snap['at']}  routes={snap['routes']} new={snap['new']} "
                f"resolved={snap['resolved']} accepted={snap['accepted']} "
                f"regressed={snap['regressed']}  {snap['snapshot']}"
            )


if __name__ == "__main__":
    main()

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

    args = p.parse_args()
    if args.cmd == "collect":
        from rung.collect import collect
        collect(context=args.context, out=args.out)
    elif args.cmd == "ingest":
        from rung.ingest import ingest
        ingest(snapshot_path=args.snapshot, stats=args.stats)


if __name__ == "__main__":
    main()

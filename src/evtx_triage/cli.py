from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from .parser import read_events
from .rules import run_all


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="evtx-triage", description="Offline Windows event log triage")
    ap.add_argument("paths", nargs="+", help=".evtx files or folders containing them")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    args = ap.parse_args(argv)

    events = read_events(args.paths)
    findings = run_all(events)

    if args.json:
        json.dump([f.to_dict() for f in findings], sys.stdout, indent=2)
        print()
        return 0

    counts = Counter(e.event_id for e in events)
    print(f"Parsed {len(events)} watched events: " + ", ".join(f"{k}x{v}" for k, v in sorted(counts.items())))
    if not findings:
        print("No findings.")
        return 0
    for f in findings:
        print(f"[{f.severity.upper():6}] {f.rule}: {f.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

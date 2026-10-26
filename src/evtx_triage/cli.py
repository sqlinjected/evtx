from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from .parser import read_events
from .rules import run_all, sort_findings


def _score_with_model(findings, quiet: bool) -> tuple[bool, int]:
    """Run MiniLM over service installs. Returns (model_ran, installs the rules missed)."""
    if not any(f.rule == "service_install" for f in findings):
        return False, 0
    try:
        from .anomaly import ServiceScorer, apply, load_minilm
        if not quiet:
            print("Loading all-MiniLM-L6-v2 (22M params, local ONNX). First run downloads ~90 MB...", file=sys.stderr)
        scorer = ServiceScorer(load_minilm())
    except ImportError:
        print('Note: model not installed, showing keyword rules only. Install it with: pip install -e ".[ml]"',
              file=sys.stderr)
        return False, 0
    return True, apply(findings, scorer)


def _run_eval() -> int:
    try:
        from .anomaly import leave_one_out, load_minilm
        embed = load_minilm()
    except ImportError:
        print('The model is not installed. Install it with: pip install -e ".[ml]"', file=sys.stderr)
        return 1
    r = leave_one_out(embed)
    print(f"Leave-one-out on {r.total} reference service installs (each one hidden, then classified):")
    for name, n in r.correct.items():
        print(f"  {name:28} {n:2}/{r.total} correct ({n / r.total:.0%})")
    print()
    for name, wrong in r.misses.items():
        print(f"  {name} got wrong: " + (", ".join(wrong) or "none"))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="evtx-triage", description="Offline Windows event log triage")
    ap.add_argument("paths", nargs="*", help=".evtx files or folders containing them")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    ap.add_argument("--no-model", action="store_true", help="keyword rules only, skip MiniLM scoring")
    ap.add_argument("--demo", action="store_true", help="run on built-in synthetic events (no logs needed)")
    ap.add_argument("--eval", action="store_true", help="leave-one-out accuracy: MiniLM vs keyword rules")
    args = ap.parse_args(argv)

    if args.eval:
        return _run_eval()

    if args.demo:
        from .demo import demo_events
        events = demo_events()
    elif args.paths:
        events = read_events(args.paths)
    else:
        ap.error("give .evtx files or folders, or use --demo")

    findings = run_all(events)
    model_ran, missed = (False, 0) if args.no_model else _score_with_model(findings, quiet=args.json)
    findings = sort_findings(findings)

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
        score = f"  [model {f.anomaly:+.2f}]" if f.anomaly is not None else ""
        print(f"[{f.severity.upper():6}] {f.rule}: {f.summary}{score}")
        if f.note:
            print(f"         {f.note}")
    if model_ran:
        print(f"\nMiniLM flagged {missed} service install(s) that the keyword rules rated low.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""python -m triage --sarif S --bandit B --project NAME [options]"""
import argparse
import json
import sys
from datetime import date

from .core import (SEVERITIES, apply_suppressions, dedupe, diff_baseline, gate,
                   load_bandit, load_semgrep_sarif, load_suppressions)


def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _group_dict(g):
    return {"key": g.key, "path": g.path, "line": g.line, "severity": g.severity,
            "tools": g.tools, "fingerprints": g.fingerprints}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="triage")
    parser.add_argument("--sarif", required=True)
    parser.add_argument("--bandit", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--equivalences")
    parser.add_argument("--baseline")
    parser.add_argument("--suppressions")
    parser.add_argument("--today")
    parser.add_argument("--fail-on", default="high", choices=SEVERITIES)
    args = parser.parse_args(argv)

    try:
        today = date.fromisoformat(args.today) if args.today else date.today()
        findings = load_semgrep_sarif(args.sarif, args.project) + load_bandit(args.bandit, args.project)
        equivalences = _read_json(args.equivalences) if args.equivalences else {}
        baseline = set(_read_json(args.baseline)) if args.baseline else set()
        entries = _read_json(args.suppressions) if args.suppressions else []
    except (OSError, ValueError, TypeError, AttributeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    groups = dedupe(findings, equivalences)
    valid, invalid = load_suppressions(entries)
    active, suppressed = apply_suppressions(groups, valid, today)
    new, existing, fixed = diff_baseline(active, baseline)
    passed = gate(new, args.fail_on)

    print(json.dumps({
        "passed": passed,
        "new": [_group_dict(g) for g in new],
        "existing": [_group_dict(g) for g in existing],
        "suppressed": [_group_dict(g) for g in suppressed],
        "fixed": fixed,
        "invalid_suppressions": len(invalid),
    }, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
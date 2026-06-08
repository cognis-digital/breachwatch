"""Command-line interface for BREACHWATCH."""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import SEVERITY_ORDER, load_sources, triage

_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def _render_table(report) -> str:
    s = report.summary
    lines = [
        f"BREACHWATCH triage — {report.generated_at}",
        f"identities: {', '.join(report.identities)}",
        "",
        f"total exposures : {s['total_exposures']}",
        f"plaintext pws   : {s['plaintext_passwords']}",
        f"affected ids    : {s['affected_identities']}",
        f"max score       : {s['max_score']}",
        "severity        : "
        + "  ".join(f"{k}={v}" for k, v in s["by_severity"].items() if v),
        "",
    ]
    if report.exposures:
        lines.append(
            f"{'SEV':<8} {'SCORE':>5}  {'SOURCE':<12} {'IDENTITY':<24} BREACH"
        )
        lines.append("-" * 78)
        for e in report.exposures:
            tag = " [PLAINTEXT]" if e.has_plaintext_password else ""
            lines.append(
                f"{e.severity:<8} {e.score:>5}  {e.source:<12} "
                f"{e.identity:<24} {e.breach}{tag}"
            )
    lines.append("")
    lines.append("ACTIONS:")
    for a in report.actions:
        lines.append(f"  - {a}")
    return "\n".join(lines)


def _cmd_triage(args) -> int:
    try:
        identities, sources = load_sources(args.config)
        report = triage(identities, **sources)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.min_severity:
        floor = _SEV_RANK[args.min_severity]
        report.exposures = [
            e for e in report.exposures if _SEV_RANK[e.severity] >= floor
        ]

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render_table(report))

    if args.fail_on:
        floor = _SEV_RANK[args.fail_on]
        if any(_SEV_RANK[e.severity] >= floor for e in report.exposures):
            return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Personal breach aggregator: HIBP + DeHashed + stealer-log triage.",
    )
    p.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser(
        "triage", help="Aggregate + risk-score breach exposures from local sources."
    )
    t.add_argument("config", help="Path to JSON config describing identities + sources.")
    t.add_argument(
        "--format", choices=["table", "json"], default="table", help="Output format."
    )
    t.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        help="Only show exposures at/above this severity.",
    )
    t.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        help="Exit code 2 if any exposure is at/above this severity (for CI/cron).",
    )
    t.set_defaults(func=_cmd_triage)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

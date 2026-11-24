#!/usr/bin/env python3
"""pktpath v3 host-side offline analysis CLI.

Subcommands:
- `show`: single-packet / multi-branch relative-µs timeline & evidence view
- `stats`: cohort admission denominators, completeness, sojourn quantiles & byte totals
- `export`: standard multi-IDB `.pcapng` exporter with evidence comments & optional `--redact`
- `redact`: keyed SHA-256 session & packet-header privacy redactor
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

# Ensure `analyzer` is importable regardless of current working directory
_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from analyzer import (  # noqa: E402
    WireError,
    attach_tcpdump_candidates,
    compute_stats,
    export_pcapng,
    filter_samples,
    reconstruct_session,
    redact_session,
    render_show_json,
    render_show_text,
    render_stats_text,
)


def _configure_stdio_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if callable(reconf):
            try:
                reconf(encoding="utf-8", errors="replace")
            except Exception:
                pass


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pktpath.py",
        description="pktpath v3 offline single-packet path reconstruction & analysis tool",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    # 1. show
    p_show = sub.add_parser(
        "show",
        help="Render single-packet / multi-branch timeline with 4-tier evidence labels",
    )
    p_show.add_argument("run_dir", help="Path to captured session directory")
    p_show.add_argument("--sample-id", type=int, default=None, help="Filter by sample_id")
    p_show.add_argument("--object-id", type=int, default=None, help="Filter by object_id")
    p_show.add_argument("--tcp-seq", type=lambda s: int(s, 0), default=None, help="Filter by TCP seq")
    p_show.add_argument("--uid", type=int, default=None, help="Filter by socket UID")
    p_show.add_argument(
        "--tcpdump",
        default=None,
        metavar="EXT_PCAP",
        help="Optional external .pcap/.pcapng file attached strictly as Level-3 annotations",
    )
    p_show.add_argument(
        "--evidence",
        action="store_true",
        help="Include raw event_id, probe symbol/version, adapter, and unknown TLV hex",
    )
    p_show.add_argument("--json", action="store_true", help="Output structured JSON")

    # 2. stats
    p_stats = sub.add_parser(
        "stats",
        help="Compute admission denominators, completeness, queue p50/p95/p99 sojourn & byte totals",
    )
    p_stats.add_argument("run_dir", help="Path to captured session directory")
    p_stats.add_argument(
        "--group-by",
        choices=("path", "leaf", "status", "uid"),
        default="path",
        help="Cohort grouping dimension (default: path)",
    )
    p_stats.add_argument("--json", action="store_true", help="Output structured JSON")

    # 3. export
    p_export = sub.add_parser(
        "export",
        help="Export captured packet headers to multi-interface .pcapng",
    )
    p_export.add_argument("run_dir", help="Path to captured session directory")
    p_export.add_argument(
        "--format",
        choices=("pcapng",),
        default="pcapng",
        required=True,
        help="Export file format (pcapng)",
    )
    p_export.add_argument("--out", required=True, help="Output .pcapng file path")
    p_export.add_argument(
        "--redact",
        action="store_true",
        help="Anonymize MAC/IP/port headers and zero L4 payload via keyed SHA-256",
    )
    p_export.add_argument(
        "--key",
        default=None,
        help="Optional redaction secret key (defaults to ephemeral random 256-bit key)",
    )
    p_export.add_argument("--json", action="store_true", help="Output export summary as JSON")

    # 4. redact
    p_redact = sub.add_parser(
        "redact",
        help="Create a privacy-redacted copy of a session directory via keyed SHA-256 truncation",
    )
    p_redact.add_argument("in_dir", help="Input session directory")
    p_redact.add_argument("--out", required=True, help="Output redacted session directory")
    p_redact.add_argument(
        "--key",
        default=None,
        help="Optional redaction secret key (defaults to ephemeral random 256-bit key)",
    )
    p_redact.add_argument("--json", action="store_true", help="Output redaction summary as JSON")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _configure_stdio_utf8()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        if args.subcommand == "show":
            session = reconstruct_session(args.run_dir)
            if args.tcpdump:
                attach_tcpdump_candidates(session, args.tcpdump)
            matched = filter_samples(
                session,
                sample_id=args.sample_id,
                object_id=args.object_id,
                tcp_seq=args.tcp_seq,
                uid=args.uid,
            )
            if args.json:
                payload = render_show_json(session, matched, evidence=args.evidence)
                print(json.dumps(payload, ensure_ascii=False, indent=2))
            else:
                print(render_show_text(session, matched, evidence=args.evidence))
            return 0

        if args.subcommand == "stats":
            session = reconstruct_session(args.run_dir)
            stats_dict = compute_stats(session, group_by=args.group_by)
            if args.json:
                print(json.dumps(stats_dict, ensure_ascii=False, indent=2))
            else:
                print(render_stats_text(stats_dict))
            return 0

        if args.subcommand == "export":
            result = export_pcapng(
                args.run_dir,
                args.out,
                redact=args.redact,
                redact_key=args.key,
            )
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            elif result["metadata_only"]:
                print(
                    f"Exported 0 packet-header blocks to {result['out_path']} "
                    "(metadata-only session; valid SHB written)."
                )
            else:
                print(
                    f"Exported {result['exported_packets']} packet-header block(s) across "
                    f"{result['interfaces']} IDB interface(s) to {result['out_path']}."
                )
            return 0

        if args.subcommand == "redact":
            result = redact_session(args.in_dir, args.out, key=args.key)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(
                    f"Redacted {result['summaries_redacted']} summary record(s) across "
                    f"{result['blocks_written']} block(s) -> {result['out_dir']}"
                )
            return 0

    except (WireError, FileNotFoundError, ValueError) as exc:
        print(f"pktpath error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

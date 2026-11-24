"""Command line interface for defanger."""

from __future__ import annotations

import argparse
import csv
import io
import json
import shutil
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .core import (
    IOC,
    KINDS,
    STYLES,
    defang_text,
    defang_value,
    expand,
    extract,
    find_iocs,
    is_defanged,
    refang_text,
)

COMMANDS = ("auto", "defang", "refang", "extract", "check")

DESCRIPTION = """\
Defang and refang indicators of compromise (IP addresses, domains, URLs, email addresses).

  defanger 1.2.3.4 evil.com           defang values given on the command line
  defanger -f report.md -o safe.md    defang every indicator in a file
  cat iocs.txt | defanger refang      refang piped data
  defanger extract -f report.md       list the indicators in a report
  defanger check -f report.md         exit 1 if a report still has live indicators

With no command, the direction is chosen automatically: input that already contains defang
markers such as [.] or hxxp is refanged, anything else is defanged.
"""


@dataclass
class Source:
    label: str
    text: str
    path: Path | None = None  # set for real files


# --------------------------------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------------------------------
def _kinds(value: str) -> list[str]:
    out: list[str] = []
    for item in value.split(","):
        item = item.strip().lower()
        if not item:
            continue
        if item == "ip":
            out += ["ipv4", "ipv6"]
        elif item in KINDS:
            out.append(item)
        else:
            raise argparse.ArgumentTypeError(f"unknown type '{item}' (choose from: ip, {', '.join(KINDS)})")
    if not out:
        raise argparse.ArgumentTypeError("no types given")
    return out


def _build_parser() -> argparse.ArgumentParser:
    inputs = argparse.ArgumentParser(add_help=False)
    inputs.add_argument("text", nargs="*", help="values or text to process (default: read stdin)")
    inputs.add_argument("-f", "--file", action="append", default=[], metavar="FILE", help="read a file ('-' is stdin); repeatable")
    inputs.add_argument("-o", "--output", metavar="FILE", help="write the result to a file instead of stdout")
    inputs.add_argument("-q", "--quiet", action="store_true", help="no messages on stderr")

    match = argparse.ArgumentParser(add_help=False)
    match.add_argument("--only", type=_kinds, metavar="TYPES", help=f"limit to these types: ip, {', '.join(KINDS)} (comma separated)")
    match.add_argument("--include-ambiguous", action="store_true",
                       help="also treat bare names like setup.py or readme.md as domains (they are TLDs too)")

    style = argparse.ArgumentParser(add_help=False)
    style.add_argument("--style", choices=sorted(STYLES), default="brackets",
                       help="brackets: evil[.]com  parens: evil(.)com  word: evil[dot]com (default: brackets)")
    style.add_argument("--colon", action="store_true", help="also defang the colon-slashes of URLs: hxxp[://]evil[.]com")

    parser = argparse.ArgumentParser(
        prog="defanger", description=DESCRIPTION, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-V", "--version", action="version", version=f"defanger {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")

    p = sub.add_parser("auto", parents=[inputs, match, style], help="defang or refang, whichever the input needs (default)")
    p.add_argument("-i", "--in-place", action="store_true", help="rewrite the -f files (a .bak copy is kept)")
    p.add_argument("--no-backup", action="store_true", help="with --in-place: do not keep a .bak copy")
    p.add_argument("--stats", action="store_true", help="print a count per indicator type to stderr")

    p = sub.add_parser("defang", parents=[inputs, match, style], help="defang indicators")
    p.add_argument("-i", "--in-place", action="store_true", help="rewrite the -f files (a .bak copy is kept)")
    p.add_argument("--no-backup", action="store_true", help="with --in-place: do not keep a .bak copy")
    p.add_argument("--stats", action="store_true", help="print a count per indicator type to stderr")

    p = sub.add_parser("refang", parents=[inputs], help="restore defanged indicators ([.] (.) [dot] [@] [at] [:] hxxp fxp)")
    p.add_argument("-i", "--in-place", action="store_true", help="rewrite the -f files (a .bak copy is kept)")
    p.add_argument("--no-backup", action="store_true", help="with --in-place: do not keep a .bak copy")

    p = sub.add_parser("extract", parents=[inputs, match, style], help="list the indicators in the input (defanged or not)")
    p.add_argument("--format", choices=("text", "json", "csv"), default="text", help="output format (default: text)")
    p.add_argument("--live", action="store_true", help="text format: print live values instead of defanged ones")
    p.add_argument("--expand", action="store_true", help="also list the host of each URL and the domain of each email")
    p.add_argument("--all", action="store_true", help="keep duplicates")

    p = sub.add_parser("check", parents=[inputs, match, style], help="exit 1 if the input contains live (not defanged) indicators")
    p.add_argument("--ignore", action="append", default=[], metavar="VALUE",
                   help="allow this domain (and its subdomains) or IP; repeatable or comma separated")
    return parser


# --------------------------------------------------------------------------------------------------
# Input and output
# --------------------------------------------------------------------------------------------------
def _read_sources(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[Source]:
    sources: list[Source] = [Source("<arg>", t) for t in args.text]
    for name in args.file:
        if name == "-":
            sources.append(Source("<stdin>", sys.stdin.read()))
            continue
        path = Path(name)
        try:
            sources.append(Source(name, path.read_bytes().decode("utf-8", errors="replace"), path))
        except OSError as exc:
            parser.exit(2, f"defanger: cannot read {name}: {exc.strerror or exc}\n")
    if not sources:
        if sys.stdin.isatty():
            parser.error("no input: give values, -f FILE, or pipe data on stdin")
        sources.append(Source("<stdin>", sys.stdin.read()))
    return sources


def _emit(args: argparse.Namespace, results: list[tuple[Source, str]]) -> None:
    """Write transformed text: in place, to -o, or to stdout."""
    if getattr(args, "in_place", False):
        for src, out in results:
            if src.path is None:
                continue
            if not args.no_backup:
                shutil.copy2(src.path, src.path.with_name(src.path.name + ".bak"))
            src.path.write_text(out, encoding="utf-8", newline="")
        return
    chunks = [out if src.path is not None or src.label == "<stdin>" else out + "\n" for src, out in results]
    if args.output and args.output != "-":
        Path(args.output).write_text("".join(chunks), encoding="utf-8", newline="")
    else:
        sys.stdout.write("".join(chunks))


# --------------------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------------------
def _run_transform(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.in_place and not args.file:
        parser.error("--in-place needs -f FILE")
    sources = _read_sources(args, parser)
    stats: Counter = Counter()
    refanged = 0
    results: list[tuple[Source, str]] = []
    for src in sources:
        text = src.text
        direction = args.command
        if direction == "auto":
            direction = "refang" if is_defanged(text) else "defang"
        if direction == "refang":
            out = refang_text(text)
            refanged += int(out != text)
        else:
            out = defang_text(
                text,
                style=args.style,
                only=args.only,
                colon=args.colon,
                include_ambiguous=args.include_ambiguous,
                stats=stats,
            )
        results.append((src, out))
    _emit(args, results)
    if getattr(args, "stats", False) and not args.quiet:
        if stats:
            print("defanged: " + ", ".join(f"{n} {k}" for k, n in sorted(stats.items())), file=sys.stderr)
        if refanged:
            print(f"refanged {refanged} input(s)", file=sys.stderr)
        if not stats and not refanged:
            print("nothing to change", file=sys.stderr)
    return 0


def _run_extract(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    sources = _read_sources(args, parser)
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for src in sources:
        for ioc in extract(
            src.text,
            only=args.only,
            expand_hosts=args.expand,
            include_ambiguous=args.include_ambiguous,
            unique=False,
        ):
            key = (ioc.kind, ioc.value.lower() if ioc.kind in ("domain", "email") else ioc.value)
            if not args.all and key in seen:
                continue
            seen.add(key)
            rows.append({
                "type": ioc.kind,
                "value": ioc.value,
                "defanged": defang_value(ioc.kind, ioc.value, style=args.style, colon=args.colon),
                "source": src.label,
            })
    out = _format_rows(rows, args)
    if args.output and args.output != "-":
        Path(args.output).write_text(out, encoding="utf-8", newline="")
    else:
        sys.stdout.write(out)
    if not args.quiet and not rows:
        print("no indicators found", file=sys.stderr)
    return 0


def _format_rows(rows: list[dict[str, str]], args: argparse.Namespace) -> str:
    if args.format == "json":
        return json.dumps(rows, indent=2, ensure_ascii=False) + "\n"
    if args.format == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["type", "value", "defanged", "source"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        return buf.getvalue()
    return "".join(f"{r['value'] if args.live else r['defanged']}\n" for r in rows)


def _ignored(ioc: IOC, ignore: set[str]) -> bool:
    """Is the indicator, or the host it points at, on the allow list?"""
    if not ignore:
        return False
    candidates = [ioc.value.lower()] + [sub.value.lower() for sub in expand(ioc)]
    return any(c == allowed or c.endswith("." + allowed) for c in candidates for allowed in ignore)


def _run_check(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    ignore = {v.strip().lower() for item in args.ignore for v in item.split(",") if v.strip()}
    sources = _read_sources(args, parser)
    hits = 0
    for src in sources:
        for number, line in enumerate(src.text.splitlines(), start=1):
            for ioc in find_iocs(line, include_ambiguous=args.include_ambiguous):
                if args.only and ioc.kind not in args.only:
                    continue
                if _ignored(ioc, ignore):
                    continue
                hits += 1
                if not args.quiet:
                    shown = defang_value(ioc.kind, ioc.value, style=args.style, colon=args.colon)
                    print(f"{src.label}:{number}: live {ioc.kind}: {shown}")
    if not args.quiet:
        print(f"{hits} live indicator(s) found" if hits else "no live indicators found", file=sys.stderr)
    return 1 if hits else 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "-V", "--version")):
        argv.insert(0, "auto")
    args = parser.parse_args(argv)
    try:
        if args.command == "extract":
            return _run_extract(args, parser)
        if args.command == "check":
            return _run_check(args, parser)
        return _run_transform(args, parser)
    except BrokenPipeError:  # e.g. piped into head
        return 0
    except ValueError as exc:
        parser.exit(2, f"defanger: {exc}\n")

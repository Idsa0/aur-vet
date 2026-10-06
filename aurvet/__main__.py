"""aurvet command line."""

from __future__ import annotations

import os
import sys

from . import __version__
from .deps import official_names
from . import state as statemod
from .lists import load as load_badlists
from .report import Verdict, render_json, render_text
from .verify import Env, Opts, resolve_names, vet_many

PROG = "aurvet"


def build_parser():
    import argparse
    p = argparse.ArgumentParser(
        prog=PROG,
        description="Heuristic pre-install screening for AUR packages. "
                    "Read-only: fetches metadata and package contents from the AUR, "
                    "runs heuristics, and cross-checks known-bad lists. "
                    "Installs nothing and does not prove a package safe.",
        epilog="exit codes: 0=clean 1=review 2=reject 3=error (see RUNBOOK.md)",
    )
    p.add_argument("packages", nargs="*", metavar="PACKAGE",
                   help="AUR package name(s) to vet (omit with --watch)")
    p.add_argument("-j", "--json", action="store_true", help="JSON output")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--deep", action="store_true",
                   help="recursively full-vet AUR-only dependencies (default: "
                        "lite checks + known-bad list only)")
    p.add_argument("--max-depth", type=int, default=3,
                   help="recursion depth for --deep (default 3)")
    p.add_argument("--no-refresh", action="store_true",
                   help="use cached known-bad lists and metadata if present")
    p.add_argument("--no-diff", action="store_true",
                   help="do not print unified diffs of changed files")
    p.add_argument("--clear", action="store_true",
                   help="record each vetted package's current state as cleared "
                        "(after reading its report!)")
    p.add_argument("--watch", action="store_true",
                   help="re-check every previously cleared package for changes")
    p.add_argument("--state", metavar="PATH", default=None,
                   help=f"state file (default {statemod.default_state_path()})")
    p.add_argument("-V", "--version", action="version", version=f"{PROG} {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    color = not args.no_color and sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    env_notes: list[str] = []
    state_path = args.state or statemod.default_state_path()
    try:
        bad = load_badlists(refresh=not args.no_refresh)
        if bad.degraded:
            env_notes.append("known-bad lists could not be fully loaded "
                             "(network/cache) - list cross-check is degraded")
        official, official_src = official_names()
        if not official:
            env_notes.append("official package names unavailable "
                             "(no pacman DB?) - shadowing/typosquat checks skipped")
        else:
            env_notes.append(f"official names: {len(official)} ({official_src})")

        state = statemod.load(state_path)
        opts = Opts(deep=args.deep, max_depth=args.max_depth,
                    show_diff=not args.no_diff, clear=args.clear)

        env = Env(bad=bad, official=official, official_src=official_src, state=state)
        env.notes.extend(env_notes)

        if args.watch:
            names = sorted(state["packages"].keys())
            if not names:
                print(f"{PROG}: no cleared packages in {state_path} "
                      "(vet one first with --clear)", file=sys.stderr)
                return Verdict.ERROR.value
        else:
            if not args.packages:
                build_parser().print_usage(sys.stderr)
                print(f"{PROG}: no PACKAGE given (or use --watch)", file=sys.stderr)
                return Verdict.ERROR.value
            names, failures = resolve_names(args.packages, env)
            env.notes.extend(
                f"no usable AUR package named {n!r} - not vetted" for n in failures
            )
            if not names:
                if args.json:
                    print(render_json([], env.notes))
                else:
                    for note in env.notes:
                        print(f"note: {note}")
                return Verdict.ERROR.value
        reports = vet_many(names, opts, env)
        if args.watch:
            for r in reports:
                if not r.changed_files and not r.new_commits \
                        and not r.findings and r.verdict == Verdict.CLEAN:
                    r.notes.append("unchanged since cleared")

        if args.clear:
            statemod.save(state_path, state)
            env.notes.append(f"cleared state recorded for "
                             f"{', '.join(r.name for r in reports if r.verdict != Verdict.ERROR)} "
                             f"in {state_path}")

        if args.json:
            print(render_json(reports, env.notes))
        else:
            print(render_text(reports, env.notes, color=color,
                              show_diff=opts.show_diff), end="")
        return max((r.verdict for r in reports), default=Verdict.CLEAN).value
    except KeyboardInterrupt:
        print(f"{PROG}: interrupted", file=sys.stderr)
        return Verdict.ERROR.value
    except Exception as e:  # top-level guard
        print(f"{PROG}: fatal: {e}", file=sys.stderr)
        return Verdict.ERROR.value


if __name__ == "__main__":
    sys.exit(main())

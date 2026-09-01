import argparse
import contextlib
import json
import sys
from pathlib import Path

from . import discovery, report
from .model import Finding
from .rules import run_all
from .rules.config import run_config

_FINDING_FIELDS = {f.name for f in __import__("dataclasses").fields(Finding)}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help"):
        from .tui import print_help
        print_help()
        return

    p = argparse.ArgumentParser(prog="frapsec", description="Frappe security scanner")
    sub = p.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="scan a bench or app")
    scan.add_argument("target_type", choices=["bench", "app", "site"])
    scan.add_argument("path")
    scan.add_argument("--format", choices=["text", "json", "sarif", "html", "markdown"], default="text")
    scan.add_argument("--semgrep-rules",
                      default=str(Path(__file__).parent / "semgrep_rules"),
                      help="semgrep rules dir (default: bundled frapsec rules); "
                           "requires semgrep on PATH, skipped if absent")
    scan.add_argument("--no-semgrep", action="store_true", help="skip the semgrep layer")
    scan.add_argument("--no-bandit", action="store_true", help="skip the bandit layer")
    scan.add_argument("--no-secrets-scan", action="store_true", help="skip the detect-secrets layer")
    scan.add_argument("--secrets-history", action="store_true",
                      help="also scan git history for committed credentials — a key removed "
                           "in a later commit is still live in history; off by default because "
                           "it walks the log")
    scan.add_argument("--history-commits", type=int, default=2000, metavar="N",
                      help="how many commits back --secrets-history walks (default 2000)")
    scan.add_argument("--only", metavar="CATEGORY", action="append",
                      choices=["api", "business", "database", "hooks", "permissions", "tenancy", "config"],
                      help="restrict native rules to this category (repeatable). Also restricts "
                           "config.py to the 'config' bucket. External layers (semgrep/bandit/"
                           "detect-secrets) have no clean category mapping and are SKIPPED "
                           "entirely when --only is set -- use --no-semgrep etc explicitly if "
                           "you want them alongside a category filter.")
    scan.add_argument("--diff", metavar="REF",
                      help="only report findings in files changed vs git REF (PR mode)")
    scan.add_argument("--baseline", metavar="PATH",
                      help="only report findings not already accepted in this baseline file")
    scan.add_argument("--update-baseline", action="store_true",
                      help="write all current findings to --baseline as accepted, then exit")
    scan.add_argument("--plain", action="store_true",
                      help="plain text output even on a terminal (no colors/table)")
    perms = sub.add_parser("permissions", help="dump role -> DocType permission matrix")
    perms.add_argument("path", help="app path")
    perms.add_argument("--format", choices=["text", "json"], default="text")

    verify = sub.add_parser("verify", help="confirm static findings against a REAL site (dynamic mode)")
    verify.add_argument("findings_json", help="JSON output from a prior `frapsec scan --format json` run")
    verify.add_argument("--site", required=True, metavar="URL", help="e.g. https://staging.example.com")
    verify.add_argument("--api-key", default="", help="or set FRAPSEC_API_KEY -- never type a real secret "
                                                        "as a plain CLI arg (shows up in shell history/ps)")
    verify.add_argument("--api-secret", default="", help="or set FRAPSEC_API_SECRET")
    verify.add_argument("--username", default="", help="alternative to --api-key/--api-secret; or set FRAPSEC_USERNAME")
    verify.add_argument("--password", default="", help="or set FRAPSEC_PASSWORD")
    verify.add_argument("--confirm", action="store_true",
                        help="required: this makes real network calls to --site with the given "
                             "credentials. Use a disposable/low-privilege account, never Administrator "
                             "-- Administrator can reach everything, so every result comes back "
                             "'reachable' and tells you nothing about who else could.")
    verify.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv)

    if args.cmd == "permissions":
        app = discovery.discover_app(args.path)
        matrix = report.permission_matrix(app)
        print(json.dumps(matrix, indent=2) if args.format == "json" else report.matrix_text(matrix))
        return

    if args.cmd == "verify":
        if not args.confirm:
            p.error("verify makes real network calls to --site -- pass --confirm to proceed "
                     "(use a disposable/low-privilege account, never Administrator)")
        import os
        api_key = args.api_key or os.environ.get("FRAPSEC_API_KEY", "")
        api_secret = args.api_secret or os.environ.get("FRAPSEC_API_SECRET", "")
        username = args.username or os.environ.get("FRAPSEC_USERNAME", "")
        password = args.password or os.environ.get("FRAPSEC_PASSWORD", "")
        if not ((api_key and api_secret) or (username and password)):
            p.error("verify needs credentials: --api-key/--api-secret or --username/--password "
                     "(or the FRAPSEC_API_KEY/FRAPSEC_API_SECRET/FRAPSEC_USERNAME/FRAPSEC_PASSWORD "
                     "env vars, so you never have to type a secret as a plain CLI arg)")
        if username.lower() == "administrator":
            p.error("refusing to verify as Administrator -- it can reach everything, so every result "
                     "comes back 'reachable' and tells you nothing about who else could. Create a "
                     "disposable low-privilege user for this instead.")

        import dataclasses
        from . import dynamic
        interactive = args.format == "text" and sys.stdout.isatty()
        console = None
        if interactive:
            from rich.console import Console
            from .tui import print_banner
            console = Console()
            print_banner(console, mode="dynamic")

        raw = json.loads(Path(args.findings_json).read_text())
        findings = [Finding(**{k: v for k, v in row.items() if k in _FINDING_FIELDS}) for row in raw]
        dynamic.verify(findings, args.site, api_key=api_key, api_secret=api_secret,
                        username=username, password=password)

        if args.format == "json":
            print(json.dumps([dataclasses.asdict(f) for f in findings], indent=2))
        elif interactive:
            from .tui import render_verify
            render_verify(findings, console)
        else:
            for f in findings:
                if f.endpoint:
                    print(f"[{f.verified.upper():10}] {f.endpoint}  ({f.rule_id}, was {f.severity})")
        return

    interactive = args.format == "text" and not args.plain and sys.stdout.isatty()
    console = None
    if interactive:
        from rich.console import Console
        from .tui import print_banner
        console = Console()
        print_banner(console, mode="static")

    def spin(message: str):
        from .tui import status
        return status(message, console) if interactive else _noop()

    with spin("Discovering apps, sites, DocTypes, endpoints..."):
        apps, sites = [], []
        if args.target_type == "bench":
            apps = discovery.discover_bench(args.path)
            sites = discovery.discover_sites(args.path)
        elif args.target_type == "app":
            apps = [discovery.discover_app(args.path)]
        else:  # site: path to sites/<name> dir
            site_dir = Path(args.path)
            sites = [s for s in discovery.discover_sites(str(site_dir.parent.parent)) if s.name == site_dir.name]

    only = set(args.only) if args.only else None

    with spin("Running rules..."):
        findings = run_all(apps, only=only if only is None else (only - {"config"}))
        if only is None or "config" in only:
            findings += run_config(sites)
    if only is None:
        if not args.no_semgrep:
            from . import semgrep
            with spin("Running semgrep..."):
                findings += semgrep.run(args.semgrep_rules, args.path)
        if not args.no_bandit:
            from . import bandit_scan
            with spin("Running bandit..."):
                findings += bandit_scan.run(args.path)
        if not args.no_secrets_scan:
            from . import secrets_scan
            with spin("Running detect-secrets..."):
                findings += secrets_scan.run(args.path)
        if getattr(args, "secrets_history", False):
            from . import secrets_history
            with spin("Scanning git history for secrets..."):
                findings += secrets_history.run(args.path, max_commits=args.history_commits)
    if args.diff:
        import subprocess
        changed = subprocess.run(
            ["git", "-C", args.path, "diff", "--name-only", args.diff],
            capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        changed = {str((Path(args.path) / c).resolve()) for c in changed}
        findings = [f for f in findings if str(Path(f.file).resolve()) in changed]

    if args.update_baseline:
        if not args.baseline:
            p.error("--update-baseline requires --baseline PATH")
        from . import baseline
        n = baseline.save(args.baseline, findings)
        print(f"Baseline written: {n} finding(s) accepted at {args.baseline}")
        return
    if args.baseline:
        from . import baseline
        findings = baseline.filter_new(findings, baseline.load(args.baseline))

    if interactive:
        from .tui import render
        render(findings, console)
    else:
        fmt = {"text": report.to_text, "json": report.to_json,
               "sarif": report.to_sarif, "html": report.to_html,
               "markdown": report.to_markdown}[args.format]
        print(fmt(findings))
    sys.exit(1 if any(f.severity in ("critical", "high") for f in findings) else 0)


@contextlib.contextmanager
def _noop():
    yield


if __name__ == "__main__":
    main()

import argparse
import json
import sys
from pathlib import Path

from . import discovery, report
from .rules import run_all
from .rules.config import run_config


def main(argv=None):
    p = argparse.ArgumentParser(prog="frapsec", description="Frappe security scanner")
    sub = p.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="scan a bench or app")
    scan.add_argument("target_type", choices=["bench", "app", "site"])
    scan.add_argument("path")
    scan.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text")
    scan.add_argument("--semgrep-rules",
                      default=str(Path(__file__).parent / "semgrep_rules"),
                      help="semgrep rules dir (default: bundled frapsec rules); "
                           "requires semgrep on PATH, skipped if absent")
    scan.add_argument("--no-semgrep", action="store_true", help="skip the semgrep layer")
    scan.add_argument("--diff", metavar="REF",
                      help="only report findings in files changed vs git REF (PR mode)")
    scan.add_argument("--baseline", metavar="PATH",
                      help="only report findings not already accepted in this baseline file")
    scan.add_argument("--update-baseline", action="store_true",
                      help="write all current findings to --baseline as accepted, then exit")
    perms = sub.add_parser("permissions", help="dump role -> DocType permission matrix")
    perms.add_argument("path", help="app path")
    perms.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv)

    if args.cmd == "permissions":
        app = discovery.discover_app(args.path)
        matrix = report.permission_matrix(app)
        print(json.dumps(matrix, indent=2) if args.format == "json" else report.matrix_text(matrix))
        return

    apps, sites = [], []
    if args.target_type == "bench":
        apps = discovery.discover_bench(args.path)
        sites = discovery.discover_sites(args.path)
    elif args.target_type == "app":
        apps = [discovery.discover_app(args.path)]
    else:  # site: path to sites/<name> dir
        site_dir = Path(args.path)
        sites = [s for s in discovery.discover_sites(str(site_dir.parent.parent)) if s.name == site_dir.name]

    findings = run_all(apps) + run_config(sites)
    if not args.no_semgrep:
        from . import semgrep
        findings += semgrep.run(args.semgrep_rules, args.path)
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

    fmt = {"text": report.to_text, "json": report.to_json,
           "sarif": report.to_sarif, "html": report.to_html}[args.format]
    print(fmt(findings))
    sys.exit(1 if any(f.severity in ("critical", "high") for f in findings) else 0)


if __name__ == "__main__":
    main()

import argparse
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
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--semgrep-rules",
                      default=str(Path(__file__).parent / "semgrep_rules"),
                      help="semgrep rules dir (default: bundled frapsec rules); "
                           "requires semgrep on PATH, skipped if absent")
    scan.add_argument("--no-semgrep", action="store_true", help="skip the semgrep layer")
    args = p.parse_args(argv)

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
    fmt = {"text": report.to_text, "json": report.to_json, "sarif": report.to_sarif}[args.format]
    print(fmt(findings))
    sys.exit(1 if any(f.severity in ("critical", "high") for f in findings) else 0)


if __name__ == "__main__":
    main()

import argparse
import sys

from . import discovery, report
from .rules import run_all


def main(argv=None):
    p = argparse.ArgumentParser(prog="frapsec", description="Frappe security scanner")
    sub = p.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="scan a bench or app")
    scan.add_argument("target_type", choices=["bench", "app"])
    scan.add_argument("path")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    args = p.parse_args(argv)

    if args.target_type == "bench":
        apps = discovery.discover_bench(args.path)
    else:
        apps = [discovery.discover_app(args.path)]

    findings = run_all(apps)
    fmt = {"text": report.to_text, "json": report.to_json, "sarif": report.to_sarif}[args.format]
    print(fmt(findings))
    sys.exit(1 if any(f.severity in ("critical", "high") for f in findings) else 0)


if __name__ == "__main__":
    main()

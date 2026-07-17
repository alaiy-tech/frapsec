"""Rich terminal rendering for interactive `frapsec scan` runs.

Used only when stdout is a real terminal (--plain or a pipe/redirect falls
back to report.to_text). Same severity colors as the HTML report
(catalog.SEVERITY_COLORS) so a terminal glance and the HTML report agree.
"""
from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .model import Finding
from .report import sort_findings
from .rules.catalog import SEVERITY_COLORS

_ORDER = ("critical", "high", "medium", "low", "info")

_LOGO = r"""
  ___                        _
 / _ \                      | |
| |_| |_ __ __ _ _ __  ___  ___  ___
|  _  | '__/ _` | '_ \/ __|/ _ \/ __|
| | | | | | (_| | |_) \__ \  __/ (__
|_| |_|_|  \__,_| .__/|___/\___|\___|
                | |
                |_|""".strip("\n")


def print_banner(console: Console | None = None) -> None:
    console = console or Console()
    body = Text(_LOGO, style="bold cyan")
    body.append(f"\nFrappe/ERPNext security scanner  ·  v{__version__}", style="dim")
    console.print(Panel(body, border_style="cyan", expand=False, padding=(0, 2)))


def print_help(console: Console | None = None) -> None:
    console = console or Console()
    print_banner(console)
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold green")
    table.add_column()
    rows = [
        ("frapsec scan bench <path>", "scan an entire bench (apps + sites config audit)"),
        ("frapsec scan app <path>", "scan one app"),
        ("frapsec scan site <path>", "scan one site's config only"),
        ("frapsec permissions <app>", "dump the role -> DocType permission matrix"),
        ("", ""),
        ("--format text|json|sarif|html", "output format (default: text)"),
        ("--diff <ref>", "PR mode: only files changed vs a git ref"),
        ("--baseline <path>", "only show findings not already accepted"),
        ("--update-baseline", "accept all current findings into --baseline"),
        ("--no-semgrep", "skip the semgrep layer"),
        ("--plain", "no colors/table even on a terminal"),
    ]
    for a, b in rows:
        table.add_row(a, b)
    console.print(table)
    console.print("\n[dim]Full flag reference: frapsec scan --help[/dim]")


def render(findings: list[Finding], console: Console | None = None) -> None:
    console = console or Console()
    findings = sort_findings(findings)
    counts = Counter(f.severity for f in findings)

    summary = Text()
    for sev in _ORDER:
        if not counts.get(sev):
            continue
        summary.append(f" {sev.upper()} {counts[sev]} ", style=f"bold white on {SEVERITY_COLORS[sev]}")
        summary.append(" ")
    console.print(summary if findings else Text("No findings.", style="bold green"))
    if not findings:
        return
    console.print()

    table = Table(show_lines=False, expand=True, pad_edge=False)
    table.add_column("Sev", width=8, no_wrap=True)
    table.add_column("Rule", width=16, no_wrap=True, style="dim")
    table.add_column("Finding", ratio=3)
    table.add_column("Location", ratio=2, style="cyan", no_wrap=False, overflow="fold")

    for f in findings:
        table.add_row(
            Text(f.severity.upper(), style=f"bold {SEVERITY_COLORS.get(f.severity, 'white')}"),
            f.rule_id,
            f.message,
            f"{f.file}:{f.line}",
        )
    console.print(table)
    console.print(f"\n[bold]{len(findings)}[/bold] finding(s).")


def status(message: str, console: Console | None = None):
    """Context manager: a spinner while discovery/rules run (scans of large
    apps take real time — a silent CLI for 15s looks broken)."""
    return (console or Console()).status(f"[bold cyan]{message}")

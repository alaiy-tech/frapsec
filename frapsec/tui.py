"""Rich terminal rendering for interactive `frapsec scan` runs.

Used only when stdout is a real terminal (--plain or a pipe/redirect falls
back to report.to_text). Same severity colors as the HTML report
(catalog.SEVERITY_COLORS) so a terminal glance and the HTML report agree.
"""
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .model import Finding
from .rules.catalog import SEVERITY_COLORS

_ORDER = ("critical", "high", "medium", "low", "info")


def render(findings: list[Finding], console: Console | None = None) -> None:
    console = console or Console()
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

    for f in sorted(findings, key=lambda f: _ORDER.index(f.severity) if f.severity in _ORDER else 9):
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

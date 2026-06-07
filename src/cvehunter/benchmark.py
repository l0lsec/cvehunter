"""Benchmark runner — evaluates the pipeline against known CVEs.

Loads benchmark definitions from tests/benchmarks/known_cves.json,
runs each CVE through the pipeline, and produces a summary report.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

BENCHMARKS_PATH = (
    Path(__file__).resolve().parent.parent.parent / "tests" / "benchmarks" / "known_cves.json"
)

# Pipeline statuses that count as a completed assessment.
_SUCCESS_STATUSES = {"judged", "completed", "approved_by_human"}

console = Console()


def load_benchmarks(
    path: Path = BENCHMARKS_PATH,
    *,
    filter_difficulty: str | None = None,
    filter_type: str | None = None,
) -> list[dict[str, Any]]:
    """Load and optionally filter benchmark CVE definitions."""
    data = json.loads(path.read_text())
    cves = data.get("cves", [])
    if filter_difficulty:
        cves = [c for c in cves if c.get("difficulty") == filter_difficulty]
    if filter_type:
        cves = [c for c in cves if c.get("type") == filter_type]
    return cves


async def run_single(cve_entry: dict[str, Any]) -> dict[str, Any]:
    """Run the pipeline for one benchmark CVE and capture metrics."""
    from cvehunter.pipeline import run_pipeline

    cve_id = cve_entry["cve_id"]
    record: dict[str, Any] = {
        "cve_id": cve_id,
        "name": cve_entry.get("name", ""),
        "difficulty": cve_entry.get("difficulty", ""),
        "type": cve_entry.get("type", ""),
    }

    start = time.monotonic()
    try:
        state = await run_pipeline(cve_id)
        record["elapsed_s"] = round(time.monotonic() - start, 2)
        record["status"] = state.get("status", "unknown")
        record["cost_usd"] = state.get("total_cost_usd", 0.0)

        judgement = state.get("judgement")
        if judgement:
            record["exploitability_score"] = judgement.exploitability_score
            record["exploit_genuine"] = judgement.exploit_genuine
        else:
            record["exploitability_score"] = None
            record["exploit_genuine"] = None

        exploit = state.get("exploit_result")
        record["flag_captured"] = exploit.flag_captured if exploit else False
        record["total_attempts"] = exploit.total_attempts if exploit else 0
        record["error"] = None
    except Exception as exc:
        record["elapsed_s"] = round(time.monotonic() - start, 2)
        record["status"] = "error"
        record["error"] = str(exc)
        record["cost_usd"] = 0.0
        record["exploitability_score"] = None
        record["exploit_genuine"] = None
        record["flag_captured"] = False
        record["total_attempts"] = 0

    return record


def print_summary(results: list[dict[str, Any]]) -> None:
    """Print a rich table summarising all benchmark results."""
    table = Table(title="CVEHunter Benchmark Results", show_lines=True)
    table.add_column("CVE", style="bold")
    table.add_column("Name")
    table.add_column("Difficulty")
    table.add_column("Status")
    table.add_column("Score", justify="right")
    table.add_column("Flag?", justify="center")
    table.add_column("Attempts", justify="right")
    table.add_column("Cost ($)", justify="right")
    table.add_column("Time (s)", justify="right")

    for r in results:
        score = f"{r['exploitability_score']:.1f}" if r["exploitability_score"] is not None else "-"
        flag = "Y" if r["flag_captured"] else "N"
        status_style = "green" if r["status"] in _SUCCESS_STATUSES else "red"
        table.add_row(
            r["cve_id"],
            r["name"],
            r["difficulty"],
            f"[{status_style}]{r['status']}[/{status_style}]",
            score,
            flag,
            str(r["total_attempts"]),
            f"{r['cost_usd']:.2f}",
            f"{r['elapsed_s']:.1f}",
        )

    console.print(table)

    total = len(results)
    successes = sum(1 for r in results if r["flag_captured"])
    total_cost = sum(r["cost_usd"] for r in results)
    total_time = sum(r["elapsed_s"] for r in results)

    console.print(f"\n[bold]Summary:[/bold] {successes}/{total} CVEs exploited")
    console.print(f"Total cost: ${total_cost:.2f}")
    console.print(f"Total time: {total_time:.1f}s")


def save_report(results: list[dict[str, Any]], output_path: Path) -> None:
    """Write the full results to a JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(results, indent=2, default=str))
    console.print(f"\nReport saved to {output_path}")


async def run_benchmarks(
    *,
    filter_difficulty: str | None = None,
    filter_type: str | None = None,
    dry_run: bool = False,
    output: str | None = None,
) -> list[dict[str, Any]]:
    """Main entry point: load benchmarks, run pipeline, report."""
    cves = load_benchmarks(
        filter_difficulty=filter_difficulty, filter_type=filter_type
    )

    if not cves:
        console.print("[yellow]No matching benchmark CVEs found.[/yellow]")
        return []

    console.print(f"[bold]Running {len(cves)} benchmark CVE(s)...[/bold]\n")

    if dry_run:
        for c in cves:
            console.print(f"  [dim]Would run:[/dim] {c['cve_id']} ({c.get('name', '')})")
        return []

    results: list[dict[str, Any]] = []
    for cve in cves:
        console.print(f"  Running {cve['cve_id']} ({cve.get('name', '')})...")
        record = await run_single(cve)
        results.append(record)
        if record["error"]:
            console.print(f"    [red]Error: {record['error']}[/red]")
        else:
            console.print(
                f"    Status: {record['status']} | "
                f"Score: {record.get('exploitability_score', '-')} | "
                f"Cost: ${record['cost_usd']:.2f} | "
                f"Time: {record['elapsed_s']:.1f}s"
            )

    print_summary(results)

    if output:
        save_report(results, Path(output))

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the CVEHunter pipeline against benchmark CVEs"
    )
    parser.add_argument(
        "--difficulty",
        choices=["easy", "medium", "hard"],
        help="Filter benchmarks by difficulty level",
    )
    parser.add_argument(
        "--type",
        dest="filter_type",
        help="Filter benchmarks by vulnerability type (e.g., rce, sqli)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List matching CVEs without running the pipeline",
    )
    parser.add_argument(
        "--output", "-o",
        help="Path to write JSON results report",
    )

    args = parser.parse_args()

    asyncio.run(
        run_benchmarks(
            filter_difficulty=args.difficulty,
            filter_type=args.filter_type,
            dry_run=args.dry_run,
            output=args.output,
        )
    )


if __name__ == "__main__":
    main()

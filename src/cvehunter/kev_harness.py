"""Automated KEV benchmarking harness.

Fetches the CISA Known Exploited Vulnerabilities catalog, identifies new
(unprocessed) entries, and runs them through the pipeline. Results are
persisted to a local SQLite database for longitudinal tracking.
"""

from __future__ import annotations

import argparse
import asyncio
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.table import Table

from cvehunter.config import settings

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Pipeline statuses that count as a completed assessment.
_SUCCESS_STATUSES = {"judged", "completed", "approved_by_human"}

console = Console()


def _db_path() -> Path:
    settings.artifact_dir.mkdir(parents=True, exist_ok=True)
    return settings.artifact_dir / "kev_runs.db"


def _init_db(db: sqlite3.Connection) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS kev_runs (
            cve_id       TEXT PRIMARY KEY,
            vendor       TEXT,
            product      TEXT,
            date_added   TEXT,
            status       TEXT,
            exploitability_score REAL,
            cost_usd     REAL,
            elapsed_s    REAL,
            run_at       TEXT,
            error        TEXT
        )
    """)
    db.commit()


def _load_processed(db: sqlite3.Connection) -> set[str]:
    rows = db.execute("SELECT cve_id FROM kev_runs").fetchall()
    return {r[0] for r in rows}


def _save_result(db: sqlite3.Connection, record: dict[str, Any]) -> None:
    db.execute(
        """
        INSERT OR REPLACE INTO kev_runs
            (cve_id, vendor, product, date_added, status,
             exploitability_score, cost_usd, elapsed_s, run_at, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["cve_id"],
            record.get("vendor", ""),
            record.get("product", ""),
            record.get("date_added", ""),
            record.get("status", "unknown"),
            record.get("exploitability_score"),
            record.get("cost_usd", 0.0),
            record.get("elapsed_s", 0.0),
            datetime.now(UTC).isoformat(),
            record.get("error"),
        ),
    )
    db.commit()


async def fetch_kev_catalog() -> list[dict[str, Any]]:
    """Download the CISA KEV catalog and return the vulnerability list."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(KEV_FEED_URL)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        console.print(
            f"[red]Could not fetch the CISA KEV catalog: {e}[/red]\n"
            "[dim]Check your network connection and try again.[/dim]"
        )
        return []
    return data.get("vulnerabilities", [])


async def _run_single_kev(kev_entry: dict[str, Any]) -> dict[str, Any]:
    """Run the pipeline for one KEV entry and capture metrics."""
    from cvehunter.pipeline import run_pipeline

    cve_id = kev_entry["cveID"].strip().upper()
    record: dict[str, Any] = {
        "cve_id": cve_id,
        "vendor": kev_entry.get("vendorProject", ""),
        "product": kev_entry.get("product", ""),
        "date_added": kev_entry.get("dateAdded", ""),
    }

    start = time.monotonic()
    try:
        state = await run_pipeline(cve_id)
        record["elapsed_s"] = round(time.monotonic() - start, 2)
        record["status"] = state.get("status", "unknown")
        record["cost_usd"] = state.get("total_cost_usd", 0.0)

        judgement = state.get("judgement")
        record["exploitability_score"] = (
            judgement.exploitability_score if judgement else None
        )
        record["error"] = None
    except Exception as exc:
        record["elapsed_s"] = round(time.monotonic() - start, 2)
        record["status"] = "error"
        record["error"] = str(exc)
        record["cost_usd"] = 0.0
        record["exploitability_score"] = None

    return record


def _print_summary(results: list[dict[str, Any]]) -> None:
    table = Table(title="KEV Benchmark Results", show_lines=True)
    table.add_column("CVE", style="bold")
    table.add_column("Vendor")
    table.add_column("Product")
    table.add_column("Status")
    table.add_column("Score", justify="right")
    table.add_column("Cost ($)", justify="right")
    table.add_column("Time (s)", justify="right")

    for r in results:
        score = (
            f"{r['exploitability_score']:.1f}"
            if r["exploitability_score"] is not None
            else "-"
        )
        status_style = "green" if r["status"] in _SUCCESS_STATUSES else "red"
        table.add_row(
            r["cve_id"],
            r.get("vendor", ""),
            r.get("product", ""),
            f"[{status_style}]{r['status']}[/{status_style}]",
            score,
            f"{r['cost_usd']:.2f}",
            f"{r['elapsed_s']:.1f}",
        )

    console.print(table)

    total = len(results)
    successes = sum(1 for r in results if r["status"] in _SUCCESS_STATUSES)
    total_cost = sum(r["cost_usd"] for r in results)
    console.print(f"\n[bold]Summary:[/bold] {successes}/{total} KEVs processed successfully")
    console.print(f"Total cost: ${total_cost:.2f}")


async def run_kev_harness(
    *,
    max_new: int = 10,
    filter_vendor: str | None = None,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    """Fetch the KEV catalog, find new entries, and run them through the pipeline."""
    console.print("[bold]Fetching CISA KEV catalog...[/bold]")
    kevs = await fetch_kev_catalog()
    console.print(f"  Total KEVs in catalog: {len(kevs)}")

    db = sqlite3.connect(_db_path())
    _init_db(db)
    processed = _load_processed(db)
    console.print(f"  Previously processed: {len(processed)}")

    new_kevs = [k for k in kevs if k["cveID"] not in processed]
    if filter_vendor:
        vendor_lower = filter_vendor.lower()
        new_kevs = [k for k in new_kevs if vendor_lower in k.get("vendorProject", "").lower()]

    new_kevs = new_kevs[:max_new]

    if not new_kevs:
        console.print("[yellow]No new KEVs to process.[/yellow]")
        db.close()
        return []

    console.print(f"[bold]Processing {len(new_kevs)} new KEV(s)...[/bold]\n")

    if dry_run:
        for k in new_kevs:
            console.print(
                f"  [dim]Would run:[/dim] {k['cveID']} "
                f"({k.get('vendorProject', '')} / {k.get('product', '')})"
            )
        db.close()
        return []

    results: list[dict[str, Any]] = []
    for kev in new_kevs:
        console.print(
            f"  Running {kev['cveID']} "
            f"({kev.get('vendorProject', '')} / {kev.get('product', '')})..."
        )
        record = await _run_single_kev(kev)
        _save_result(db, record)
        results.append(record)

        if record["error"]:
            console.print(f"    [red]Error: {record['error']}[/red]")
        else:
            console.print(
                f"    Status: {record['status']} | "
                f"Score: {record.get('exploitability_score', '-')} | "
                f"Cost: ${record['cost_usd']:.2f}"
            )

    db.close()
    _print_summary(results)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run CVEHunter against new CISA KEV entries"
    )
    parser.add_argument(
        "--max",
        type=int,
        default=10,
        help="Maximum number of new KEVs to process (default: 10)",
    )
    parser.add_argument(
        "--vendor",
        help="Filter KEVs by vendor name (case-insensitive substring match)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List new KEVs without running the pipeline",
    )

    args = parser.parse_args()

    asyncio.run(
        run_kev_harness(
            max_new=args.max,
            filter_vendor=args.vendor,
            dry_run=args.dry_run,
        )
    )


if __name__ == "__main__":
    main()

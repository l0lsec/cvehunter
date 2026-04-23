"""CLI entry point for MOAK-Lite."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="moak",
        description="MOAK-Lite: Autonomous CVE exploitation pipeline",
    )
    subparsers = parser.add_subparsers(dest="command")

    # `moak run <CVE-ID>`
    run_parser = subparsers.add_parser("run", help="Run the pipeline for a CVE")
    run_parser.add_argument("cve_id", help="CVE identifier (e.g., CVE-2024-12345)")
    run_parser.add_argument("--output", "-o", help="Output file for the report (JSON)")

    # `moak collect <CVE-ID>` — run only the Collector
    collect_parser = subparsers.add_parser("collect", help="Run only the Collector agent")
    collect_parser.add_argument("cve_id", help="CVE identifier")

    # `moak status` — show pipeline status
    subparsers.add_parser("status", help="Show pipeline configuration and status")

    args = parser.parse_args()

    if args.command == "run":
        asyncio.run(_run_pipeline(args.cve_id, args.output))
    elif args.command == "collect":
        asyncio.run(_run_collector(args.cve_id))
    elif args.command == "status":
        _show_status()
    else:
        parser.print_help()
        sys.exit(1)


async def _run_pipeline(cve_id: str, output_file: str | None) -> None:
    from moak.pipeline import run_pipeline

    console.print(Panel(f"[bold]MOAK-Lite Pipeline[/bold]\nTarget: {cve_id}", style="blue"))

    try:
        result = await run_pipeline(cve_id)

        judgement = result.get("judgement")
        if judgement:
            table = Table(title="Judgement Report")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("CVE", cve_id)
            table.add_row("Exploitability Score", str(judgement.exploitability_score))
            table.add_row("Exploit Genuine", str(judgement.exploit_genuine))
            table.add_row("Environment Realistic", str(judgement.environment_realistic))
            table.add_row("HITL Level", judgement.hitl_level)
            table.add_row("Shortcut Detected", str(judgement.shortcut_detected))
            console.print(table)
            console.print(f"\n[bold]Summary:[/bold] {judgement.summary}")

        if output_file:
            with open(output_file, "w") as f:
                json.dump(result, f, indent=2, default=str)
            console.print(f"\nReport saved to: {output_file}")

    except Exception as e:
        console.print(f"[red]Pipeline failed: {e}[/red]")
        sys.exit(1)


async def _run_collector(cve_id: str) -> None:
    from moak.agents.collector import run_collector

    console.print(Panel(f"[bold]Collector Agent[/bold]\nTarget: {cve_id}", style="blue"))

    try:
        result = await run_collector({"cve_id": cve_id})
        cve_package = result.get("cve_package")
        if cve_package:
            console.print_json(cve_package.model_dump_json(indent=2))
    except Exception as e:
        console.print(f"[red]Collector failed: {e}[/red]")
        sys.exit(1)


def _show_status() -> None:
    from moak.config import AGENT_MODEL_MAPPING, MODELS, settings

    table = Table(title="MOAK-Lite Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Anthropic API Key", "***" if settings.anthropic_api_key else "[red]NOT SET[/red]")
    table.add_row("DeepSeek API Key", "***" if settings.deepseek_api_key else "[red]NOT SET[/red]")
    table.add_row("NVD API Key", "***" if settings.nvd_api_key else "[yellow]optional[/yellow]")
    table.add_row("GitHub Token", "***" if settings.github_token else "[yellow]optional[/yellow]")
    table.add_row("Max Cost/CVE", f"${settings.max_cost_per_cve}")
    table.add_row("Max Monthly Spend", f"${settings.max_monthly_spend}")
    table.add_row("Docker Host", settings.docker_host)
    table.add_row("Artifact Dir", str(settings.artifact_dir))

    console.print(table)

    model_table = Table(title="Agent → Model Mapping")
    model_table.add_column("Agent", style="cyan")
    model_table.add_column("Tier", style="yellow")
    model_table.add_column("Model", style="green")
    model_table.add_column("Cost (in/out)", style="magenta")

    for agent, tier in AGENT_MODEL_MAPPING.items():
        model = MODELS[tier]
        model_table.add_row(
            agent,
            tier.value,
            model.model_name,
            f"${model.cost_per_1m_input}/{model.cost_per_1m_output} per 1M",
        )

    console.print(model_table)


if __name__ == "__main__":
    main()

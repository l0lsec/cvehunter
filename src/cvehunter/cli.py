"""CLI entry point for CVEHunter (argparse-based)."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from langgraph.errors import GraphInterrupt
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cvehunter.logging_config import setup_logging

console = Console()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cvehunter",
        description="CVEHunter: Autonomous CVE exploitation pipeline",
    )
    subparsers = parser.add_subparsers(dest="command")

    # `cvehunter run <CVE-ID>`
    run_parser = subparsers.add_parser("run", help="Run the pipeline for a CVE")
    run_parser.add_argument("cve_id", help="CVE identifier (e.g., CVE-2024-12345)")
    run_parser.add_argument("--output", "-o", help="Output file for the report (JSON)")
    run_parser.add_argument(
        "--simple-researcher",
        action="store_true",
        help="Use single-model researcher instead of the multi-model swarm",
    )

    # `cvehunter collect <CVE-ID>` — run only the Collector
    collect_parser = subparsers.add_parser("collect", help="Run only the Collector agent")
    collect_parser.add_argument("cve_id", help="CVE identifier")

    # `cvehunter resume <CVE-ID>` — resume a paused/failed pipeline
    resume_parser = subparsers.add_parser(
        "resume", help="Resume a paused or failed pipeline run from its last checkpoint"
    )
    resume_parser.add_argument("cve_id", help="CVE identifier")

    # `cvehunter approve <CVE-ID>` — approve an HITL-paused run
    approve_parser = subparsers.add_parser(
        "approve", help="Approve a pipeline paused at the HITL gate"
    )
    approve_parser.add_argument("cve_id", help="CVE identifier")
    approve_parser.add_argument("--notes", default="", help="Optional reviewer notes")

    # `cvehunter reject <CVE-ID>` — reject an HITL-paused run
    reject_parser = subparsers.add_parser(
        "reject", help="Reject a pipeline paused at the HITL gate"
    )
    reject_parser.add_argument("cve_id", help="CVE identifier")
    reject_parser.add_argument("--notes", default="", help="Reason for rejection")

    # `cvehunter status` — show pipeline status
    subparsers.add_parser("status", help="Show pipeline configuration and status")

    # `cvehunter llms` — show active LLMs, balances, and monthly spend
    subparsers.add_parser(
        "llms",
        help="Show active LLMs, live provider balances, and monthly spend",
    )

    args = parser.parse_args()
    setup_logging()

    if hasattr(args, "cve_id") and args.cve_id:
        args.cve_id = args.cve_id.strip().upper()

    if args.command == "run":
        if args.simple_researcher:
            from cvehunter.config import settings as _settings
            _settings.researcher_swarm_enabled = False
        asyncio.run(_run_pipeline(args.cve_id, args.output))
    elif args.command == "collect":
        asyncio.run(_run_collector(args.cve_id))
    elif args.command == "resume":
        asyncio.run(_resume_pipeline(args.cve_id))
    elif args.command == "approve":
        asyncio.run(_hitl_respond(args.cve_id, action="approve", notes=args.notes))
    elif args.command == "reject":
        asyncio.run(_hitl_respond(args.cve_id, action="reject", notes=args.notes))
    elif args.command == "status":
        _show_status()
    elif args.command == "llms":
        asyncio.run(_show_llms())
    else:
        parser.print_help()
        sys.exit(1)


async def _run_pipeline(cve_id: str, output_file: str | None) -> None:
    from cvehunter.config import settings
    from cvehunter.pipeline import run_pipeline

    settings.validate_keys()
    setup_logging(cve_id=cve_id)
    console.print(Panel(f"[bold]CVEHunter Pipeline[/bold]\nTarget: {cve_id}", style="blue"))

    try:
        result = await run_pipeline(cve_id)

        # When the Judge flags medium/high HITL, the graph pauses at the gate;
        # ainvoke returns the state with an "__interrupt__" marker. Surface it
        # and tell the user how to resume instead of pretending the run finished.
        if isinstance(result, dict) and result.get("__interrupt__"):
            console.print(
                Panel(
                    f"[bold yellow]Paused for human review[/bold yellow]\n"
                    f"The Judge flagged {cve_id} for human-in-the-loop review.\n\n"
                    f"Approve: [cyan]cvehunter approve {cve_id}[/cyan]\n"
                    f"Reject:  [cyan]cvehunter reject {cve_id}[/cyan]",
                    style="yellow",
                )
            )
            judgement = result.get("judgement")
            if judgement:
                console.print(
                    f"\n[bold]Provisional score:[/bold] {judgement.exploitability_score}"
                    f"  [bold]HITL level:[/bold] {judgement.hitl_level}"
                )
                console.print(f"[bold]Summary:[/bold] {judgement.summary}")
            return

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

        from cvehunter.config import settings as _settings

        poc_path = _settings.pocs_dir / f"{cve_id}.py"
        if poc_path.exists():
            exploit = result.get("exploit_result")
            captured = bool(getattr(exploit, "flag_captured", False))
            label = "verified PoC" if captured else "best-attempt PoC"
            console.print(f"\n[bold]PoC ({label}):[/bold] {poc_path}")

        if output_file:
            with open(output_file, "w") as f:
                json.dump(result, f, indent=2, default=str)
            console.print(f"\nReport saved to: {output_file}")

    except GraphInterrupt:
        console.print(
            f"[yellow]Pipeline paused at the HITL gate. "
            f"Use 'cvehunter approve {cve_id}' or 'cvehunter reject {cve_id}' to resume.[/yellow]"
        )
        return
    except Exception as e:
        console.print(f"[red]Pipeline failed: {e}[/red]")
        sys.exit(1)


async def _resume_pipeline(cve_id: str) -> None:
    from cvehunter.pipeline import resume_pipeline

    console.print(Panel(f"[bold]Resuming Pipeline[/bold]\nTarget: {cve_id}", style="yellow"))
    try:
        result = await resume_pipeline(cve_id)
        console.print(f"[green]Resumed successfully. Status: {result.get('status')}[/green]")
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Resume failed: {e}[/red]")
        sys.exit(1)


async def _hitl_respond(cve_id: str, *, action: str, notes: str) -> None:
    from cvehunter.pipeline import resume_pipeline

    label = "Approving" if action == "approve" else "Rejecting"
    console.print(Panel(f"[bold]{label} HITL Gate[/bold]\nTarget: {cve_id}", style="yellow"))
    try:
        result = await resume_pipeline(
            cve_id,
            human_response={"action": action, "notes": notes},
        )
        console.print(f"[green]Done. Status: {result.get('status')}[/green]")
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]HITL response failed: {e}[/red]")
        sys.exit(1)


async def _run_collector(cve_id: str) -> None:
    from cvehunter.agents.collector import run_collector
    from cvehunter.config import settings

    settings.validate_keys()
    console.print(Panel(f"[bold]Collector Agent[/bold]\nTarget: {cve_id}", style="blue"))

    try:
        result = await run_collector({"cve_id": cve_id})
        cve_package = result.get("cve_package")
        if cve_package is None:
            console.print(
                f"[red]Collector failed to extract CVE data for {cve_id}.[/red]"
            )
            for err in result.get("errors", []):
                console.print(f"  [dim]{err}[/dim]")
            sys.exit(1)
        console.print_json(cve_package.model_dump_json(indent=2))
    except Exception as e:
        console.print(f"[red]Collector failed: {e}[/red]")
        sys.exit(1)


def _show_status() -> None:
    from cvehunter.config import AGENT_MODEL_MAPPING, MODELS, settings

    table = Table(title="CVEHunter Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    def _key(value: str, *, optional: bool = False) -> str:
        if value:
            return "***"
        return "[yellow]optional[/yellow]" if optional else "[red]NOT SET[/red]"

    def _toggle(enabled: bool) -> str:
        return "[green]enabled[/green]" if enabled else "[dim]disabled[/dim]"

    table.add_row("Anthropic API Key", _key(settings.anthropic_api_key))
    table.add_row("DeepSeek API Key", _key(settings.deepseek_api_key, optional=True))
    table.add_row("Google API Key", _key(settings.google_api_key, optional=True))
    table.add_row("NVD API Key", _key(settings.nvd_api_key, optional=True))
    table.add_row("GitHub Token", _key(settings.github_token, optional=True))
    table.add_row("Researcher Swarm", _toggle(settings.researcher_swarm_enabled))
    table.add_row("LangSmith Tracing", _toggle(settings.langsmith_enabled))
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


def _format_balance(status) -> str:
    """Render a ProviderBalance for display in the CLI table."""
    balance = status.balance
    if balance is None:
        return "[dim]inactive[/dim]"
    if balance.source == "live" and balance.total is not None:
        currency = balance.currency or "USD"
        return f"${balance.total:.2f} {currency}"
    note = balance.note or "dashboard only"
    return f"[yellow]{note}[/yellow]"


async def _show_llms() -> None:
    from cvehunter.llm_status import build_report

    report = await build_report(live=True)

    model_table = Table(title="Active LLMs")
    model_table.add_column("Tier", style="yellow")
    model_table.add_column("Provider", style="cyan")
    model_table.add_column("Model", style="green")
    model_table.add_column("Active", style="magenta")
    model_table.add_column("Agents", style="white")
    model_table.add_column("$/1M in", style="magenta", justify="right")
    model_table.add_column("$/1M out", style="magenta", justify="right")
    model_table.add_column("Balance", style="green")

    for status in report.models:
        active_cell = (
            "[green]yes[/green]" if status.active else "[red]no[/red]"
        )
        agents = ", ".join(status.assigned_agents) if status.assigned_agents else "[dim]—[/dim]"
        model_table.add_row(
            status.tier,
            status.provider,
            status.model_name,
            active_cell,
            agents,
            f"${status.cost_per_1m_input:.2f}",
            f"${status.cost_per_1m_output:.2f}",
            _format_balance(status),
        )

    console.print(model_table)

    spend = report.spend
    spend_table = Table(title="Monthly Spend")
    spend_table.add_column("Field", style="cyan")
    spend_table.add_column("Value", style="green")
    spend_table.add_row("Month", spend.month)
    spend_table.add_row("Spend to date", f"${spend.monthly_spend_usd:.4f}")
    spend_table.add_row("Monthly cap", f"${spend.monthly_cap_usd:.2f}")
    spend_table.add_row("Remaining", f"${spend.monthly_remaining_usd:.4f}")
    spend_table.add_row("Per-CVE cap", f"${spend.per_cve_cap_usd:.2f}")

    console.print(spend_table)

    console.print(
        "\n[dim]Note: Anthropic, OpenAI, and Google do not expose public "
        "balance endpoints; use the billing dashboard links for those.[/dim]"
    )


if __name__ == "__main__":
    main()

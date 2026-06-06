# CVEHunter

Autonomous multi-agent CVE exploitation pipeline to collect/research CVE info, build a vulnerable lab, and create a working PoC exploit for CVE.

Given a CVE ID, CVEHunter automatically:

1. **Collects** vulnerability data and patch diffs from NVD, OSV.dev, and GitHub
2. **Researches** the vulnerability to build an exploitation primitives graph and recipe
3. **Builds** isolated Docker environments with flag insertion for testing
4. **Exploits** the vulnerability through iterative code generation with a feedback loop
5. **Judges** the exploitation for genuineness and produces an exploitability score

## Architecture

```
CVE ID → Collector → Researcher → Builder → Exploiter → Judge → Report
              │           │                      ↑    │
              │           │                      └────┘ (feedback loop)
              │           └─── escalates to Opus 4.8 on hard CVEs
              └─── Claude Haiku 4.5 (cheap tier)
```

### LLM Tier Strategy

CVEHunter runs on **Anthropic models across every tier** by default. Other
providers (DeepSeek, Google, OpenAI) remain wired in the router but are optional
opt-ins — only `ANTHROPIC_API_KEY` is required to run.

| Tier  | Model             | Agents                    | Cost (in / out per 1M) |
| ----- | ----------------- | ------------------------- | ---------------------- |
| Cheap | Claude Haiku 4.5  | Collector, Builder, Judge | $1 / $5                |
| Smart | Claude Sonnet 4.6 | Researcher, Exploiter     | $3 / $15               |
| Heavy | Claude Opus 4.8   | Escalation only           | $5 / $25               |

Estimated **$3-15 per CVE** for typical web-app vulnerabilities, depending on
how many exploit iterations and escalations a CVE requires.

## Quick Start

```bash
# Clone and install
cd ~/tools/cvehunter
pip install -e ".[dev]"

# Configure API keys
cp .env.example .env
# Edit .env with your API keys

# Check configuration (API keys, model tiers, cost limits)
cvehunter status

# Show active LLMs, balances, and monthly spend
cvehunter llms

# Run the pipeline for a CVE
cvehunter run CVE-2021-44228

# Use the single-model researcher instead of the multi-model swarm
cvehunter run CVE-2021-44228 --simple-researcher

# Run only the Collector
cvehunter collect CVE-2021-44228

# A run flagged for human review pauses; approve or reject it:
cvehunter approve CVE-2021-44228
cvehunter reject CVE-2021-44228 --notes "environment looks unrealistic"

# Resume a paused or failed run from its last checkpoint
cvehunter resume CVE-2021-44228

# Start the API + web dashboard (dashboard auto-mounts at /dashboard/)
uvicorn cvehunter.api.main:app --reload
# then open http://localhost:8000/dashboard/
```

### Web Dashboard

The dashboard at `/dashboard/` has full parity with the CLI:

- **Submit** a CVE for full analysis (with an optional "simple researcher" toggle)
- **Collect only** — run just the Collector agent
- **Live progress** — per-stage stepper, cost, and recent errors while a run is active
- **HITL review** — approve/reject runs the Judge flags for human review
- **Cancel / Retry / Resume** in-flight or finished runs
- **Status** page mirroring `cvehunter status`, and an **LLMs** page mirroring `cvehunter llms`

> The dashboard drives all mutations through server-side `/dashboard/actions/*`
> handlers, so it works even when `CVEHUNTER_API_KEY` is set (which protects the
> external `/api/v1/*` REST endpoints).

## Project Structure

```
cvehunter/
  src/cvehunter/
    config.py          # Settings, model tiers, cost limits
    llm_router.py      # Tiered model selection (DeepSeek → Sonnet → Opus)
    schemas.py         # Pydantic models for all agent I/O
    pipeline.py        # LangGraph workflow orchestration
    cli.py             # Command-line interface
    agents/
      collector.py     # CVE data gathering
      researcher.py    # Vulnerability analysis + primitives graph
      builder.py       # Docker environment provisioning
      exploiter.py     # Exploit code generation + feedback loop
      judge.py         # Exploitation audit + scoring
    tools/
      nvd.py           # NVD API client
      osv.py           # OSV.dev API client
      github.py        # GitHub API client
      docker_ops.py    # Docker SDK operations
      sandbox.py       # Sandboxed exploit execution
    templates/
      dockerfiles/     # Dockerfile templates per stack
      compose/         # Docker Compose templates
    api/
      main.py          # FastAPI application (mounts the dashboard)
      routes.py        # Authenticated REST API endpoints
      run_service.py   # Auth-free run lifecycle shared by API + dashboard
      database.py      # SQLite run persistence
    dashboard/         # HTMX + Jinja2 web UI (full CLI parity)
  docs/
    PLAN.md            # Full technical plan
  tests/
    benchmarks/        # Known CVEs for testing
```

## Requirements

- Python 3.12+
- Docker (for environment provisioning and exploit sandboxing)
- API keys:
  - **Anthropic** — required (all model tiers default to Anthropic)
  - **NVD**, **GitHub** — recommended (avoid aggressive rate limits)
  - **DeepSeek**, **Google**, **OpenAI** — optional; only needed if you remap a
    tier to a non-Anthropic provider in `config.py`

## Safety Notice

This tool generates real exploits in isolated environments for defensive security research.
All exploit execution happens inside sandboxed Docker containers with no internet access.
Do not use this tool against systems you do not own or have explicit permission to test.
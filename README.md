# CVEHunter

Autonomous multi-agent CVE exploitation pipeline.

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
              │           └─── escalates to Opus 4.6 on hard CVEs
              └─── DeepSeek V4 Flash (cheap tier)
```

### LLM Tier Strategy

| Tier | Model | Agents | Cost |
|------|-------|--------|------|
| Cheap | DeepSeek V4 Flash | Collector, Builder, Judge | $0.14/1M tokens |
| Smart | Claude Sonnet 4 | Researcher, Exploiter | $3/1M tokens |
| Heavy | Claude Opus 4.6 | Escalation only | $15/1M tokens |

Estimated **$2-8 per CVE** for typical web-app vulnerabilities.

## Quick Start

```bash
# Clone and install
cd ~/tools/cvehunter
pip install -e ".[dev]"

# Configure API keys
cp .env.example .env
# Edit .env with your API keys

# Check configuration
cvehunter status

# Run the pipeline for a CVE
cvehunter run CVE-2021-44228

# Run only the Collector
cvehunter collect CVE-2021-44228

# Start the API server
uvicorn cvehunter.api.main:app --reload
```

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
      main.py          # FastAPI application
      routes.py        # REST API endpoints
  docs/
    PLAN.md            # Full technical plan
  tests/
    benchmarks/        # Known CVEs for testing
```

## Requirements

- Python 3.12+
- Docker (for environment provisioning and exploit sandboxing)
- API keys: Anthropic (required), DeepSeek (required), NVD (recommended), GitHub (recommended)

## Safety Notice

This tool generates real exploits in isolated environments for defensive security research.
All exploit execution happens inside sandboxed Docker containers with no internet access.
Do not use this tool against systems you do not own or have explicit permission to test.

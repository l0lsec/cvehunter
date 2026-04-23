# Building a MOAK-like Pipeline: Budget-Optimized Technical Plan

**Constraints:** Solo developer, $50-200/month, full CVE scope, cloud infrastructure.

---

## Architecture Overview

The pipeline consists of 5 sequential agents orchestrated via LangGraph:

1. **Collector Agent** — Gathers CVE data, patch diffs, and metadata from NVD/OSV/GitHub
2. **Researcher Agent** — Analyzes the vulnerability, builds a primitives graph, produces an exploit recipe
3. **Environment Builder Agent** — Provisions isolated Docker environments with flag insertion
4. **Exploiter Agent** — Generates and iterates on exploit code until flag is captured
5. **Judge Agent** — Audits the entire pipeline for genuineness and scores exploitability

```
CVE ID → Collector → Researcher → Builder → Exploiter → Judge → Report
                                      ↑         |
                                      └─────────┘ (feedback loop)
```

---

## LLM Tier Strategy

| Tier | Model | Cost (in/out per 1M tokens) | Used By |
|------|-------|-----------------------------|---------|
| 1 (Cheap) | DeepSeek V3.2 | $0.14 / $0.28 | Collector, Builder, Judge |
| 2 (Smart) | Claude Sonnet 4 | $3.00 / $15.00 | Researcher, Exploiter |
| 3 (Heavy) | Claude Opus 4.6 | $15.00 / $75.00 | Escalation only (hard CVEs) |

**Estimated cost per CVE:** $2-8 typical, $10-25 complex.
**At $150/month:** ~20-50 CVEs/month.

### Why API-only (no self-hosting)

Running a 70B+ parameter model requires an A100/H100 GPU (~$1-3/hour on RunPod/vast.ai).
That's $720-2,160/month — far exceeding the budget.
DeepSeek V3.2 via API is cheaper than self-hosting it.

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.12+ |
| Agent Framework | LangGraph |
| LLM APIs | Anthropic (Claude), DeepSeek (OpenAI-compatible) |
| Data Schemas | Pydantic v2 |
| Containerization | Docker SDK for Python, Docker Compose |
| Data Sources | NVD API 2.0, OSV.dev, GitHub API |
| Storage | SQLite (MVP), PostgreSQL (scale) |
| Dashboard | FastAPI + HTMX/React |
| Artifacts | Local filesystem (MinIO later) |

### Why LangGraph over CrewAI

- 40% lower token overhead (+9% vs +18%)
- Built-in checkpointing and state persistence
- Conditional branching maps perfectly to exploit feedback loops
- Human-in-the-loop support for Judge escalation
- Free observability via LangSmith

---

## Detailed Agent Designs

### Agent 1: Collector

**LLM:** DeepSeek V3.2
**Purpose:** Given a CVE ID, gather all relevant vulnerability data.

**Tools:**
- `query_nvd(cve_id)` — fetch CVE details from NVD API
- `query_osv(cve_id)` — fetch from OSV.dev (often has direct commit links)
- `github_search(query)` — search for fix commits
- `git_clone_and_diff(repo_url, commit_hash)` — clone repo, extract diff
- `scrape_advisory(url)` — fetch vendor advisory page (allowlisted domains only)

**Guardrails:** Hardcoded allowlist of domains. Block exploit-db, packetstorm, PoC repos.

**Output:** `CVEPackage` — structured data including CVE description, patch diff, affected software metadata.

### Agent 2: Researcher

**LLM:** Claude Sonnet 4 (default), escalate to Opus 4.6 on failure

**Core data structure:** Primitives Graph — a DAG where nodes are exploitation primitives and edges represent dependencies.

**MVP:** Single-model analysis producing an exploit recipe.
**Scaled:** Multi-model sub-agent swarm with role rotation (Prioritizer, Lead Researcher, Contrarian, Verifier).

### Agent 3: Environment Builder

**LLM:** DeepSeek V3.2
**Purpose:** Build isolated Docker environments for exploit testing.

**Tools:**
- `generate_dockerfile(software, version, language)` — from templates + LLM
- `docker_compose_up(compose_yaml)` — spin up environment
- `health_check(container_id, check_type)` — verify functionality
- `insert_flag(container_id, vuln_type, flag_value)` — place secret flag
- `clone_and_patch(container_id)` — create patched version

**Flag placement** varies by vulnerability type (file for path traversal, DB record for SQLi, etc.).

### Agent 4: Exploiter

**LLM:** Claude Sonnet 4
**Purpose:** Write and iterate on exploit code until flag is captured.

**Feedback loop:**
1. Write exploit code
2. Run against vulnerable environment
3. If flag captured → validate against patched environment
4. If not → analyze error logs → iterate
5. After 10 failed Sonnet attempts → escalate to Opus 4.6
6. Total cap: 15 attempts

### Agent 5: Judge

**LLM:** DeepSeek V3.2
**Purpose:** Audit the entire pipeline for genuineness.

**Checks:**
1. Correct flag captured?
2. Exploit fails on patched environment?
3. No unintended access paths in Docker config?
4. No external PoCs ingested by Collector?
5. HITL level assessment

**Output:** `JudgementReport` with exploitability score, genuineness assessment, and structured analysis.

---

## Infrastructure

- **Cloud VM:** Hetzner CAX31 (~$15-30/month) — 8 vCPU, 16GB RAM, 200GB SSD
- **Docker + Docker Compose** — no Kubernetes needed
- **Network isolation:** Docker `--internal` networks; exploit containers have no internet
- **SQLite** for MVP storage
- **Local filesystem** for artifacts

### Data Sources (All Free)

- **NVD API 2.0** — free with API key (0.6s rate limit). Python: `nvdlib`
- **GitHub API** — 5,000 req/hour authenticated
- **OSV.dev** — complements NVD with better Git commit references
- **Debian/Red Hat Security Trackers** — direct patch commit links

---

## Cost Budget Breakdown (Monthly, ~30 CVEs)

| Item | Cost |
|------|------|
| DeepSeek V3.2 (Collector, Builder, Judge) | $5-15 |
| Claude Sonnet 4 (Researcher, Exploiter) | $40-100 |
| Claude Opus 4.6 (escalation, ~5 CVEs) | $15-35 |
| Cloud VM (Hetzner) | $15-30 |
| GitHub API | Free |
| NVD API | Free |
| **Total** | **$75-180/month** |

---

## Phased Build Order

| Phase | Weeks | Deliverable |
|-------|-------|-------------|
| 1. Scaffold + LLM Router | 1-2 | Project setup, tiered model selection, Docker SDK wiring |
| 2. Collector Agent | 3-4 | NVD/OSV/GitHub integration, patch diff extraction, guardrails |
| 3. Researcher Agent (MVP) | 5-7 | Single-model vuln analysis, exploit recipe generation |
| 4. Environment Builder | 8-10 | Docker lab provisioning, flag insertion, patched env cloning |
| 5. Exploiter Agent | 11-14 | Exploit codegen, feedback loop, first end-to-end test |
| 6. Judge Agent | 15-16 | Artifact audit, shortcut detection, scoring |
| 7. Dashboard | 17-18 | FastAPI backend + lightweight frontend |
| 8. Scale-Up | 19+ | Multi-model swarm, role rotation, KEV benchmarking |

---

## Critical Decisions Summary

- **LangGraph over CrewAI** — lower overhead, checkpointing, better for feedback loops
- **DeepSeek V3.2 as cheap workhorse** — 71x cheaper than GPT-5
- **Claude Sonnet 4 as main reasoning model** — best quality-to-cost ratio with prompt caching
- **Claude Opus 4.6 as escalation only** — too expensive for every CVE
- **API-only, no self-hosting** — GPU rentals exceed budget
- **Hetzner VPS over AWS/GCP** — 3-5x cheaper for equivalent compute
- **SQLite for MVP** — zero setup, upgrade later
- **Start with web-app CVEs** — fastest validation loop before expanding to native

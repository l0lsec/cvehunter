# MOAK-Lite Development Checklist

A complete, ordered list of everything that needs to be built, fixed, or completed
for this project to run end-to-end. Items are grouped by priority and category.

Work through this list top-to-bottom. Each item is scoped to be completable in
a single focused session. Check the box when done.

---

## Phase 0: Critical Blockers (Nothing runs without these)

These must be resolved before any agent can execute.

- [ ] **0.1 — API key validation on startup**
  - File: `src/moak/config.py`
  - `Settings` allows empty strings for `anthropic_api_key` and `deepseek_api_key`. The pipeline will crash at the first LLM call with a cryptic provider error.
  - Add a `validate_keys()` method that checks required keys are set before any pipeline run. Call it from `cli.py` and `api/routes.py`.
  - Required keys: `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`.
  - Recommended keys (warn if missing): `NVD_API_KEY`, `GITHUB_TOKEN`.

- [ ] **0.2 — Wire `get_commit_diff` into the Collector agent**
  - File: `src/moak/agents/collector.py`, `src/moak/tools/github.py`
  - `get_commit_diff` is implemented in `github.py` but NOT in the `collector_tools` list. The Collector can search for commits but can never fetch the actual patch diff.
  - Add `get_commit_diff` to `collector_tools`.
  - Update `COLLECTOR_SYSTEM_PROMPT` to instruct the LLM to call `get_commit_diff` after finding a fix commit via `search_github_commits` or `fetch_osv`.

- [ ] **0.3 — Implement actual Docker environment provisioning in the Builder**
  - File: `src/moak/agents/builder.py`
  - Lines ~111-114 have TODO comments. `build_image`, `compose_up`, `health_check`, and `insert_flag` are imported but never called. The Builder currently only asks the LLM to generate YAML — it never actually spins up containers.
  - Uncomment and implement the Docker execution block:
    1. Write the generated `compose_yaml` to a temp directory
    2. Call `compose_up()` with a project name based on the CVE ID
    3. Resolve container names from the compose project
    4. Call `insert_flag()` on the appropriate container
    5. Call `health_check()` to verify the environment is running
    6. Set `env_spec.health_check_passed` based on the result
  - Handle failures: if compose_up or health_check fails, set `status: "environment_failed"` and add to `errors`.

- [ ] **0.4 — Implement actual exploit execution in the Exploiter**
  - File: `src/moak/agents/exploiter.py`, `src/moak/tools/sandbox.py`
  - Lines ~108-117 have TODO comments. The Exploiter generates exploit code but never runs it. `stdout`/`stderr` are always empty and `flag_captured` is always `False`, which means the retry loop always runs to exhaustion.
  - After the LLM generates exploit code:
    1. Import and call `sandbox.run_exploit(exploit_code, env.network_name)`
    2. Populate `attempt.stdout` and `attempt.stderr` from the sandbox result
    3. Check if `env.flag_value` appears in stdout to set `attempt.flag_captured`
    4. If flag captured, call `sandbox.run_against_patched(exploit_code, patched_network)` and set `result.fails_on_patched` based on whether the flag is NOT captured in the patched run

- [ ] **0.5 — Build the patched environment alongside the vulnerable one**
  - File: `src/moak/agents/builder.py`
  - The `EnvironmentSpec` schema has `patched_image` but the Builder never creates it. The Exploiter needs both environments for validation.
  - After building the vulnerable environment:
    1. Generate a second Dockerfile/compose using the patched version of the software
    2. Spin it up as a separate compose project (e.g., `{cve_id}-patched`)
    3. Store the patched network name in `EnvironmentSpec` (add a `patched_network_name` field to the schema)
  - This is required for the "fails on patched" validation in the Exploiter.

---

## Phase 1: Agent Implementation Gaps

- [ ] **1.1 — Enforce the Collector's domain allowlist**
  - File: `src/moak/agents/collector.py`
  - `ALLOWED_DOMAINS` is defined but never checked. The LLM could potentially call `scrape_advisory` on blocked domains.
  - Create a `validate_url(url: str) -> bool` function that checks the URL's domain against `ALLOWED_DOMAINS`.
  - Add URL validation inside `scrape_advisory` (once implemented, see 1.2) and in any tool that accepts URLs.

- [ ] **1.2 — Implement the `scrape_advisory` tool**
  - File: `src/moak/tools/` (new file: `advisory.py`)
  - Referenced in `COLLECTOR_SYSTEM_PROMPT` and `docs/PLAN.md` but does not exist.
  - Implement an async `scrape_advisory(url: str) -> dict` tool that:
    1. Validates the URL against `ALLOWED_DOMAINS`
    2. Fetches the page content with `httpx`
    3. Extracts relevant text (strip HTML, keep security-relevant content)
    4. Returns structured output with title, body text, and any linked patches
  - Add to `collector_tools` in `collector.py`.

- [ ] **1.3 — Implement the `git_clone_and_diff` tool**
  - File: `src/moak/tools/` (new file: `git_ops.py`)
  - Referenced in `COLLECTOR_SYSTEM_PROMPT` and `docs/PLAN.md` but does not exist.
  - Implement: clone a repo to a temp directory, checkout a specific commit, and extract the diff.
  - This is needed for cases where the GitHub API diff endpoint fails or the repo is on GitLab.
  - Add to `collector_tools`.

- [ ] **1.4 — Bind Docker tools to the Builder LLM**
  - File: `src/moak/agents/builder.py`
  - Unlike the Collector (which uses `llm.bind_tools()`), the Builder only uses `structured_output`. The Builder should have tools for iterative environment refinement.
  - Bind `build_image`, `compose_up`, `health_check` as tools so the LLM can iteratively fix Dockerfiles if the build fails.
  - Add a feedback loop: if `compose_up` fails, feed the error back to the LLM for correction (up to 3 retries).

- [ ] **1.5 — Wire Dockerfile templates into the Builder**
  - File: `src/moak/agents/builder.py`
  - `src/moak/templates/dockerfiles/` and `src/moak/templates/compose/` exist but are never loaded or referenced from code.
  - Add a `load_template(language: str, framework: str) -> str` function that reads the appropriate template file.
  - Include the template content in the Builder's prompt context so the LLM can use it as a starting point rather than generating from scratch.

- [ ] **1.6 — Add input guards to the Judge agent**
  - File: `src/moak/agents/judge.py`
  - The Judge assumes all upstream artifacts (`cve_package`, `exploit_recipe`, `environment`, `exploit_result`) are present and valid. If any upstream agent failed, the Judge will crash with `AttributeError`.
  - Add None-checks for each artifact and produce a partial `JudgementReport` with appropriate notes when data is missing.

- [ ] **1.7 — Use `researcher_escalation_threshold` from config**
  - File: `src/moak/agents/researcher.py`, `src/moak/config.py`
  - `settings.researcher_escalation_threshold` (set to 3) is defined but never used. Escalation currently triggers on a single failure (no complete chain).
  - Implement: track the number of research iterations. Only escalate to Opus after `researcher_escalation_threshold` failed attempts.
  - This requires adding a `researcher_attempts` counter to the pipeline state.

---

## Phase 2: Pipeline and Orchestration Gaps

- [ ] **2.1 — Integrate cost tracking with `estimate_cost`**
  - Files: `src/moak/llm_router.py`, `src/moak/pipeline.py`
  - `estimate_cost()` is implemented but never called. `total_cost_usd` in the pipeline state is always `0.0`.
  - Wrap LLM calls in each agent to capture token usage from the response metadata and update `total_cost_usd` in the state.
  - LangChain responses include `response.usage_metadata` with `input_tokens` and `output_tokens`.

- [ ] **2.2 — Enforce cost limits (per-CVE and monthly)**
  - File: `src/moak/pipeline.py` or new file `src/moak/cost_tracker.py`
  - `MAX_COST_PER_CVE` and `MAX_MONTHLY_SPEND` from settings are never checked.
  - Implement a cost tracker that:
    1. Accumulates cost per pipeline run
    2. Persists monthly spend to SQLite/file
    3. Aborts the pipeline with a clear error if either limit is exceeded
  - Add a conditional check node in the LangGraph pipeline after each agent.

- [ ] **2.3 — Use typed state instead of raw `dict`**
  - File: `src/moak/pipeline.py`
  - `StateGraph(dict)` works but loses type safety. Use a `TypedDict` matching `PipelineState` fields for the graph state, or use `PipelineState` directly with LangGraph's Pydantic state support.
  - This prevents bugs from typos in state keys and enables better IDE support.

- [ ] **2.4 — Add environment cleanup to the pipeline**
  - Files: `src/moak/pipeline.py`, `src/moak/tools/docker_ops.py`
  - `cleanup_environment()` in `docker_ops.py` is never called. Docker containers and networks are leaked after every run.
  - Add a cleanup node at the end of the pipeline (after Judge) that tears down all compose projects for the CVE.
  - Also add cleanup on pipeline failure/exception (use LangGraph's error handling or a try/finally wrapper in `run_pipeline`).

- [ ] **2.5 — Add artifact persistence**
  - File: new file `src/moak/artifacts.py`
  - `settings.artifact_dir` is configured but never used. No artifacts (exploit code, judgement reports, logs) are saved to disk.
  - Implement `save_artifacts(cve_id: str, state: dict)` that writes:
    1. `{artifact_dir}/{cve_id}/cve_package.json`
    2. `{artifact_dir}/{cve_id}/exploit_recipe.json`
    3. `{artifact_dir}/{cve_id}/environment_spec.json`
    4. `{artifact_dir}/{cve_id}/exploit_result.json` (including all attempt code)
    5. `{artifact_dir}/{cve_id}/judgement_report.json`
  - Call from `run_pipeline` after the Judge completes.

- [ ] **2.6 — Handle partial pipeline failures gracefully**
  - File: `src/moak/pipeline.py`
  - If the Collector fails (e.g., NVD API down), the Researcher receives `None` for `cve_package` and crashes.
  - Add error-handling conditional edges: if any agent produces an error state, skip to the Judge with partial data (the Judge can still produce a "could not assess" report).

---

## Phase 3: Tool Implementation Gaps

- [ ] **3.1 — Fix `compose_up` to return container names and network info**
  - File: `src/moak/tools/docker_ops.py`
  - `compose_up` currently returns only `project_name` and `stdout`. Downstream code needs container names and the Docker network name.
  - After `docker compose up`, run `docker compose -p {project_name} ps --format json` to get container names/IDs.
  - Run `docker network ls --filter name={project_name} --format json` to get the network name.
  - Return these in the result dict.

- [ ] **3.2 — Fix `insert_flag` shell injection vulnerability**
  - File: `src/moak/tools/docker_ops.py`
  - `insert_flag` uses `f"sh -c 'echo {flag_value} > {flag_location}'"` — special characters in the flag can break the command or inject.
  - Use `shlex.quote()` for both `flag_value` and `flag_location`, or write the flag via Docker SDK's `put_archive` API instead of `exec_run`.

- [ ] **3.3 — Fix NVD tool blocking the event loop**
  - File: `src/moak/tools/nvd.py`
  - `nvdlib.searchCVE` is synchronous. Inside an `async def` tool, this blocks the event loop.
  - Wrap the call in `asyncio.to_thread()` or `loop.run_in_executor()`.

- [ ] **3.4 — Add structured error handling to all tools**
  - Files: all files in `src/moak/tools/`
  - Tools return `{"error": "..."}` dicts on failure, but callers never check for this.
  - Either: raise exceptions from tools and handle in agents, or add error-checking logic in each agent after tool calls.

- [ ] **3.5 — Implement SQL-type flag insertion for the Builder**
  - File: `src/moak/tools/docker_ops.py`
  - `insert_flag` has a `"database_record"` path that returns `{"status": "flag_in_database", "instruction": ...}` but doesn't actually insert into a DB.
  - Implement: detect which DB container is running (postgres, mysql, mongo), exec an appropriate SQL/command to insert the flag record.

---

## Phase 4: Testing Gaps

- [ ] **4.1 — Add mock-based unit tests for the Collector**
  - File: `tests/test_collector.py`
  - Current tests hit live APIs. Add tests using `unittest.mock.patch` or `pytest-mock` to mock `fetch_cve`, `fetch_osv`, `search_github_commits`, and verify `run_collector` produces a valid `CVEPackage`.

- [ ] **4.2 — Add unit tests for the Researcher agent**
  - File: `tests/test_researcher.py`
  - Currently only tests the Pydantic schema. Add a test that mocks the LLM and verifies `run_researcher` produces an `ExploitRecipe` with a primitives graph.

- [ ] **4.3 — Add unit tests for Builder, Exploiter, and Judge**
  - Files: new `tests/test_builder.py`, `tests/test_exploiter.py`, `tests/test_judge.py`
  - Each should mock LLM responses and Docker operations.
  - Test the Exploiter's retry loop with simulated failures.
  - Test the Judge's handling of missing artifacts.

- [ ] **4.4 — Add an integration test for `run_pipeline`**
  - File: new `tests/test_pipeline.py`
  - Mock all LLM calls and Docker operations. Verify the full graph executes from Collector through Judge and produces a `JudgementReport`.
  - Test the conditional edges: researcher escalation, exploiter retry, exploiter give-up.

- [ ] **4.5 — Add a benchmark runner**
  - File: new `tests/run_benchmarks.py` or `src/moak/benchmark.py`
  - `tests/benchmarks/known_cves.json` has 5 known CVEs but no code to run them through the pipeline.
  - Implement a script that iterates over the benchmark CVEs, runs the pipeline, and produces a summary report (success rate, average cost, average time).

- [ ] **4.6 — Add a `conftest.py` with shared fixtures**
  - File: new `tests/conftest.py`
  - Create reusable fixtures: `sample_cve_package`, `sample_exploit_recipe`, `sample_environment_spec`, `mock_llm_response`.

---

## Phase 5: API and Dashboard Gaps

- [ ] **5.1 — Add CORS middleware to the FastAPI app**
  - File: `src/moak/api/main.py`
  - No CORS headers are set. A browser-based dashboard will be blocked.
  - Add `CORSMiddleware` with appropriate origins.

- [ ] **5.2 — Replace in-memory `_runs` with SQLite persistence**
  - File: `src/moak/api/routes.py`
  - `_runs` is a process-local dict. All data is lost on restart.
  - Use SQLite (via `settings.database_url`) with a `runs` table.
  - Add `aiosqlite` or `sqlalchemy[asyncio]` to dependencies.
  - Schema: `id`, `cve_id`, `status`, `started_at`, `completed_at`, `exploitability_score`, `summary`, `full_result_json`.

- [ ] **5.3 — Add error codes and structured error responses**
  - File: `src/moak/api/routes.py`
  - Background task errors are stored as a string. Add proper error classification and HTTP error responses.

- [ ] **5.4 — Build the dashboard frontend**
  - Directory: `src/moak/dashboard/`
  - Currently empty. Build a lightweight UI (HTMX or React) with:
    1. Form to submit a CVE ID for analysis
    2. Table/list of all runs with status, score, and timestamp
    3. Detail view for a completed run showing the full judgement report
    4. Auto-refresh for in-progress runs
  - For fastest MVP, use HTMX with Jinja2 templates served by FastAPI.

- [ ] **5.5 — Add authentication to the API**
  - File: `src/moak/api/main.py`
  - No auth at all. At minimum, add API key authentication for the `/api/v1/run` endpoint.

---

## Phase 6: Infrastructure and DevOps

- [ ] **6.1 — Remove unused `GOOGLE_API_KEY` from `.env.example` or implement Google/Gemini support**
  - Files: `.env.example`, `src/moak/config.py`, `src/moak/llm_router.py`
  - `.env.example` has `GOOGLE_API_KEY` but no code uses it. Either remove it or add Gemini as a model option in the router.

- [ ] **6.2 — Remove unused `langchain-community` dependency**
  - File: `pyproject.toml`
  - `langchain-community` is declared but never imported. Remove it to reduce install size.

- [ ] **6.3 — Verify `pip install -e .` works with the `src/` layout**
  - File: `pyproject.toml`
  - Hatchling with a `src/` layout sometimes needs `[tool.hatch.build.targets.wheel] packages = ["src/moak"]`. Test the install.

- [ ] **6.4 — Add a `Makefile` or `justfile` for common commands**
  - Targets: `install`, `test`, `lint`, `format`, `run`, `serve` (API), `clean` (Docker cleanup).

- [ ] **6.5 — Add Docker network isolation verification**
  - Verify that exploit containers on `--internal` networks truly cannot reach the internet. Add a test or startup check.

- [ ] **6.6 — Add logging throughout the pipeline**
  - Currently no structured logging. Add Python `logging` or `structlog` with:
    - Per-agent log entries (start, end, token usage, cost)
    - Tool call logs
    - Error logs with full context
  - Write logs to `{artifact_dir}/{cve_id}/pipeline.log`.

---

## Phase 7: Features for Full MOAK Parity (Post-MVP)

These are the advanced features from the MOAK paper. Build these after the core pipeline works.

- [ ] **7.1 — Multi-model sub-agent swarm for the Researcher**
  - Implement the Prioritizer, Lead Researcher, Contrarian, and Verifier sub-agents.
  - Use LangGraph's `Send` API for fan-out parallelism.
  - Rotate roles between DeepSeek, Sonnet, and Gemini across iterations.

- [ ] **7.2 — Primitives graph visualization**
  - Render the `PrimitivesGraph` as a visual DAG (using Mermaid, Graphviz, or D3).
  - Include in the judgement report and dashboard.

- [ ] **7.3 — LangSmith observability integration**
  - Add LangSmith tracing for all LLM calls. LangSmith free tier supports this.
  - Enable via environment variable `LANGCHAIN_TRACING_V2=true`.

- [ ] **7.4 — Checkpointing and resume**
  - Use LangGraph's built-in checkpointing to save pipeline state at each node.
  - Allow resuming a failed pipeline run from the last successful node.

- [ ] **7.5 — Automated KEV benchmarking harness**
  - Fetch the CISA KEV catalog automatically.
  - Run the pipeline against new KEVs as they're published.
  - Track success rates, costs, and times over time.

- [ ] **7.6 — Human-in-the-loop support**
  - Add a "pause and wait for human input" node in the pipeline.
  - Triggered by the Judge when HITL level is "medium" or "high".
  - Expose via the API/dashboard.

- [ ] **7.7 — Gemini model support in the LLM router**
  - Add `langchain-google-genai` dependency.
  - Add Gemini 3.1 Pro / Flash to `MODELS` in config.
  - Wire into the router and role rotation.

---

## Quick Reference: Build Order

For the fastest path to a working E2E pipeline:

```
0.1 → 0.2 → 0.3 → 0.4 → 0.5    (Critical blockers — makes the pipeline functional)
  ↓
1.1 → 1.2 → 1.6                  (Key agent gaps)
  ↓
2.1 → 2.4 → 2.5 → 2.6           (Pipeline robustness)
  ↓
3.1 → 3.2 → 3.3                  (Tool fixes)
  ↓
4.1 → 4.4                        (Core tests)
  ↓
6.3 → 6.6                        (Install verification + logging)
  ↓
Ship MVP, then work on Phases 5 and 7
```

Total estimated effort for Phase 0-3 (functional pipeline): **~2-3 weeks** focused work.
Total estimated effort for full checklist through Phase 6: **~6-8 weeks**.
Phase 7 (MOAK parity features): **ongoing, 4+ weeks**.

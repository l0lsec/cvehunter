"""Judge Agent — audits the pipeline for genuineness and scores exploitability.

LLM Tier: CHEAP (Claude Haiku 4.5)
Input: All artifacts from previous agents
Output: JudgementReport
"""

from __future__ import annotations

from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from cvehunter.config import ModelTier
from cvehunter.llm_router import get_model, structured_call
from cvehunter.schemas import (
    CVEPackage,
    EnvironmentSpec,
    ExploitRecipe,
    ExploitResult,
    JudgementReport,
)

logger = structlog.get_logger(__name__)

JUDGE_SYSTEM_PROMPT = """\
You are a security audit judge. Your role is to verify that an automated
exploitation was genuine, the test environment was realistic, and no shortcuts
or external information were used.

Review ALL artifacts from the pipeline and check for:

1. EXPLOIT GENUINENESS
   - Does the exploit actually target the described vulnerability?
   - Does it use the primitives identified by the Researcher?
   - Could it work in a real-world scenario?

2. ENVIRONMENT REALISM
   - Is the Docker environment realistic for the affected software?
   - Are there any unintended access paths (admin backdoors, debug modes,
     exposed management ports, default credentials beyond normal)?
   - Did the Builder accidentally make exploitation easier than it should be?

3. INFORMATION INTEGRITY
   - Did the Collector only use allowlisted sources?
   - Is there any sign that PoC code was ingested and used?
   - Does the exploit show patterns from known public exploits?

4. HITL ASSESSMENT
   - If the exploit required human intervention, what level?
   - none: fully autonomous
   - low: minor parameter tuning
   - medium: significant manual steps needed
   - high: essentially manual exploitation

5. EXPLOITABILITY SCORE (0-10)
   - 0: not exploitable
   - 1-3: theoretically possible but impractical
   - 4-6: exploitable with moderate effort
   - 7-9: easily exploitable
   - 10: trivially exploitable, script-kiddie level

Be skeptical. Look for shortcuts and false positives.

Important reporting rule:
- ``final_exploit_code`` is only populated after successful flag capture. If a
  run failed, do NOT conclude that no exploit code was generated solely because
  ``final_exploit_code`` is empty. Review the attempt history, stdout/stderr,
  target service logs, and per-attempt exploit snippets.
"""


def _truncate(value: str | None, limit: int) -> str:
    text = value or ""
    if len(text) <= limit:
        return text
    return f"{text[:limit].rstrip()}\n...[truncated {len(text) - limit} chars]"


def _attempt_summary(result: ExploitResult) -> str:
    parts: list[str] = []
    for attempt in result.attempts[-5:]:
        code = _truncate(attempt.exploit_code, 1200)
        stdout = _truncate(attempt.stdout, 1200)
        stderr = _truncate(attempt.stderr, 800)
        analysis = _truncate(attempt.error_analysis, 1000)
        logs = "\n\n".join(
            f"[{service}]\n{_truncate(logs, 1500)}"
            for service, logs in attempt.target_logs.items()
        )
        parts.append(
            f"""#### Attempt {attempt.attempt_number} (model: {attempt.model_tier_used})
- Flag captured: {attempt.flag_captured}
- Exploit code length: {len(attempt.exploit_code)} chars
- Error analysis: {analysis or '(none)'}
- stdout:
```
{stdout}
```
- stderr:
```
{stderr}
```
- target logs:
```
{logs or '(none)'}
```
- exploit snippet:
```python
{code}
```
"""
        )
    return "\n".join(parts)


async def run_judge(state: dict[str, Any]) -> dict[str, Any]:
    """Execute the Judge agent node."""
    cve_package: CVEPackage | None = state.get("cve_package")
    recipe: ExploitRecipe | None = state.get("exploit_recipe")
    env: EnvironmentSpec | None = state.get("environment")
    result: ExploitResult | None = state.get("exploit_result")

    missing = [
        name
        for name, val in [
            ("cve_package", cve_package),
            ("exploit_recipe", recipe),
            ("environment", env),
            ("exploit_result", result),
        ]
        if val is None
    ]

    run_cost = state.get("total_cost_usd", 0.0)
    tier = ModelTier.CHEAP

    if missing:
        return {
            "judgement": JudgementReport(
                cve_id=state.get("cve_id", "UNKNOWN"),
                exploitability_score=0.0,
                summary=f"Incomplete pipeline: missing {', '.join(missing)}",
                full_analysis=(
                    f"Cannot judge -- upstream agents failed to produce: {', '.join(missing)}"
                ),
            ),
            "status": "judged_partial",
            "total_cost_usd": run_cost,
        }

    llm = get_model("judge")

    context = f"""## Pipeline Audit for: {cve_package.cve_id}

### Collector Output
- CVE: {cve_package.cve_id}
- Description: {cve_package.description}
- Software: {cve_package.affected_software}
- Sources used: {', '.join(cve_package.references)}

### Researcher Output
- Vulnerability Type: {recipe.vulnerability_type}
- Attack Vector: {recipe.attack_vector}
- Exploitation Steps: {len(recipe.exploitation_steps)}
- Complete chains found: {len(recipe.primitives_graph.complete_chains)}
- Complexity: {recipe.estimated_complexity}

### Environment Builder Output
- Services: {', '.join(env.services)}
- Credentials provided: {list(env.credentials.keys())}
- Health check passed: {env.health_check_passed}
- Docker Compose:
```yaml
{env.compose_yaml[:2000]}
```

### Exploiter Output
- Success: {result.success}
- Total attempts: {result.total_attempts}
- Flag captured: {result.flag_captured}
- Fails on patched: {result.fails_on_patched}
- Attempts with generated code: {sum(1 for a in result.attempts if a.exploit_code.strip())}
- Last exploit code length: {len(result.attempts[-1].exploit_code) if result.attempts else 0}
- Final exploit code:
```python
{result.final_exploit_code[:3000]}
```
Note: final_exploit_code is expected to be empty when flag capture fails. Judge
failed runs from the attempt history below, not from final_exploit_code alone.

### Attempt History
{_attempt_summary(result)}
"""

    messages = [
        SystemMessage(content=JUDGE_SYSTEM_PROMPT),
        HumanMessage(content=context),
    ]

    report, call_cost = await structured_call(llm, JudgementReport, messages, tier)
    run_cost += call_cost

    if report is None:
        return {
            "judgement": JudgementReport(
                cve_id=cve_package.cve_id,
                exploitability_score=0.0,
                summary="Judge could not produce a structured assessment.",
                full_analysis="The judge LLM failed to return a valid JudgementReport.",
            ),
            "status": "judged_partial",
            "total_cost_usd": run_cost,
        }

    report.cve_id = cve_package.cve_id

    return {
        "judgement": report,
        "status": "judged",
        "total_cost_usd": run_cost,
    }

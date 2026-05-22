# AGENTS.md

## Mission

在这个项目中，agent 应交付小而正确、可维护、可验证的变更。先调查清楚再行动，保持 diff 聚焦，不要用一次性硬编码把当前 case 跑过。

Trace-Agent 的目标不是写“看起来能跑”的 demo，而是稳定地把安全告警调查、证据组织和报告生成串成可审计流程。任何改动都应优先保护事实边界、source 可追溯性和复杂 case 下的稳定性。

## Project Overview

Trace-Agent 是面向命中后恶意流量告警的自动化事件研判 agent。当前主线是 `incident-agent`：从 fixture 或 seed alert 出发，完成调查循环、证据结构化、交付判断、报告材料组织、报告写作和拓扑输出。

## Commands

当前仓库通常在已有 `trail-agent` conda 环境中运行。

- Run one fixture: `conda run -n trail-agent python -m demo_agent --alert fixtures/incidents/web_initial_access_to_beacon --out outputs/incident_tests/web_initial_access_to_beacon/agent --mode incident-agent`
- Heuristic 5-case smoke: `conda run -n trail-agent python tools/run_incident_smoke.py`
- LLM agent protocol smoke: `conda run -n trail-agent python tools/test_llm_agent_protocol.py`
- LLM API ping: `conda run -n trail-agent python tools/llm_ping.py --trace-path outputs/llm_ping.jsonl`
- Compile touched Python files: `conda run -n trail-agent python -m py_compile <files>`

Full live LLM regression is slow, costly, and may call external services. Ask before running broad live evals unless the user explicitly requests them.

## Project Map

- `demo_agent/incidents/agent.py` - incident-agent investigation loop, tool selection, readiness and delivery state.
- `demo_agent/incidents/report_agent.py` - report material agent loop and prompt.
- `demo_agent/incidents/report_agent_tools.py` - report material tools, source bundle helpers, validation and feedback.
- `demo_agent/incidents/report_agent_writer.py` - writer brief compilation and polished report writer path.
- `demo_agent/incidents/render.py` - report rendering entry points and artifact assembly.
- `fixtures/incidents/` - incident fixtures and expected outcomes.
- `tools/` - smoke tests, protocol checks, and LLM connectivity checks.
- `outputs/` - generated run artifacts. Do not treat these as source unless the task explicitly asks to inspect or preserve a run result.

## Agent Development Rules

- Validators should enforce structural safety, schema contracts, source/fact id validity, and required coverage. They should not turn style preferences or prose quality into blocking failures.
- If a validator emits feedback, distinguish `blocking` from `advisory`. Blocking means the downstream writer cannot safely use the material. Advisory means improve if possible, but do not force fallback or retry loops.
- Avoid case-specific hardcoding. Do not add checks that pass only because current fixture names, timestamps, assets, or paragraph wording match.
- Complex cases naturally contain candidate assets, shared infrastructure, background events, and unresolved gaps. These should usually become reportable boundaries, not automatic delivery blockers.
- Do not make confirmed incidents become `needs_review` only because every candidate expansion is not independently verified. Confirmed main chain and candidate boundary can coexist.
- Keep `approved` / `deliverable_now` separate from `preferred_stop`: a case may be reportable with explicit boundaries while still worth continuing if there are high-value, budgeted follow-up actions.
- Keep deterministic code responsible for lossless fact compilation, normalization, source id validation, and safe fallback. Keep LLM agents responsible for ambiguous routing, prioritization, and argument planning.
- Do not let fallback hide agent failure. If fallback is used, trace/status must clearly say so.
- Do not overfit report quality by expanding prompts alone. Inspect artifacts first: `incident.json`, `readiness`, `report_source_bundle.json`, `report_material_loop_trace.json`, `report_writer_materials.json`, `report_writer_brief.json`, and final report.

## Hypothesis Contract

In Trace-Agent, a `hypothesis` is not a decorative label, a richer summary, or a synonym for "topic". It is a testable claim about either the incident mechanism or an agent behavior change. A valid hypothesis must state what it predicts, what evidence would support it, what evidence would weaken or falsify it, and what agent decision it is supposed to influence.

Use three different kinds of hypotheses and keep their boundaries clear:

- Investigation hypothesis: a candidate explanation of the alert or attack chain. It should drive investigation focus, tool/action ranking, stop/continue reasoning, or the confirmed/candidate/unresolved boundary.
- Report hypothesis: a candidate narrative claim for the report. It may organize evidence, but it must not turn candidate or background material into a confirmed conclusion unless the source bundle supports that promotion.
- Experiment hypothesis: a claim about a code or prompt change. It must say which behavior should change, why this mechanism should cause the change, which artifacts or metrics will show the effect, and what result would count as failure.

Before adding or changing hypothesis-related code, answer these questions in the plan, comments, tests, or review notes:

- What behavior should change: investigation focus, tool choice, stop decision, readiness, material routing, writer grounding, or report boundary language?
- By what mechanism: what new information, ranking rule, evidence graph, prompt constraint, or validator rule causes the behavior change?
- How will it be observed: which trace, artifact, fixture outcome, or report property should move?
- What would falsify it: what output pattern proves the change is useless, unsafe, or merely cosmetic?

Success means the hypothesis changes a real decision while preserving evidence boundaries. Good outcomes include selecting a higher-value follow-up, stopping when remaining work is low-value, keeping a confirmed main chain deliverable while labeling candidate expansions as candidates, making source-grounded report claims easier to audit, or exposing a real unresolved limit.

Failure means the hypothesis is present but does not control anything. Treat it as failed if it only adds generic prose, produces longer reports without better grounding, encourages extra rounds without value-of-information or budget justification, hides uncertainty, promotes candidates into conclusions, blocks delivery only because unrelated candidates remain open, or cannot be traced back to concrete evidence and a concrete decision.

Tests and evals for hypothesis features should include negative or control cases whenever practical. A useful test should show not only when a hypothesis is supported, but also when it stays unresolved, is rejected, or should not affect delivery.

## Report Pipeline Boundaries

- `report_source_bundle` is the factual input boundary.
- `source_fact_catalog` should preserve atomic facts and exact source linkage; it must not invent facts.
- The material agent should route facts into sections and paragraph groups; it should not rewrite facts into new unsupported summaries.
- The writer should expand from deterministic facts and the route plan; it must not promote candidate or background material into confirmed conclusions.
- `section_briefs.paragraph_groups` are writing plans, not evidence themselves. Missing or invalid ids are blocking; bland labels are advisory.
- `reportable_limits` must describe real limitations, such as candidate event not validated, host logs missing, counterevidence not fully checked, or shared infrastructure ambiguity. Do not write fake limits that merely summarize report contents.

## Testing

- For report-agent or writer changes, run at least:
  - `conda run -n trail-agent python -m py_compile demo_agent/incidents/report_agent.py demo_agent/incidents/report_agent_tools.py demo_agent/incidents/report_agent_writer.py demo_agent/incidents/render.py`
  - `conda run -n trail-agent python tools/test_llm_agent_protocol.py`
  - `conda run -n trail-agent python tools/run_incident_smoke.py`
- For investigation-loop or readiness changes, inspect at least one generated `incident.json` and confirm `provisional_status`, `delivery_status`, `readiness.blocking_checks`, and `session_state.budgets` make sense together.
- For live LLM report quality, do not rely on command success. Check `material_status`, `material_validation_ok`, fallback status, report length only as a weak signal, and whether confirmed/candidate/boundary language is correct.
- If tests cannot be run, say exactly which checks were skipped and what risk remains.

## Code Style

- Follow nearby code and existing helper functions before introducing new abstractions.
- Keep changes small and targeted. Do not rewrite prompts, validators, writer, fixtures, and readiness logic in one patch unless the user explicitly asks for that scope.
- Prefer explicit helper functions over hidden prompt-only behavior when the rule is machine-checkable.
- Do not add dependencies unless the user approves.
- Use `apply_patch` for manual edits.

## Boundaries

Always do:

- Read relevant code, traces, and generated artifacts before changing behavior.
- Preserve user changes and unrelated dirty files.
- Keep generated `outputs/` changes out of source-oriented patches unless the task is specifically about eval artifacts.
- Update documentation when changing commands, workflow, validation semantics, or public report/material schema.

Ask first:

- Broad live LLM regressions, external API usage, or long-running evals.
- Deleting fixtures, outputs, or historical comparison artifacts.
- Large prompt/schema migrations or architecture changes.
- New dependencies or environment changes.

Never do:

- Commit secrets, API keys, tokens, or private data.
- Fix a failing eval by weakening a meaningful test or hiding a real failure.
- Use destructive git commands such as `git reset --hard` or force push without explicit permission.
- Add brittle wording checks that block the pipeline because a model used different but valid phrasing.

## Workflow

1. Identify the failing boundary first: investigation loop, readiness gate, material routing, writer brief, writer prose, or eval fixture.
2. Inspect the relevant artifacts before editing.
3. Make the smallest change that fixes the boundary.
4. Run the narrowest meaningful checks, then broader smoke tests if shared behavior changed.
5. Report what changed, what was verified, and what remains risky.

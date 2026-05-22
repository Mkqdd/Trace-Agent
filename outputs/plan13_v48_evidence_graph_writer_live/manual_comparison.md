# Evidence Graph A/B Manual Comparison

## Run Summary

- Output root: `outputs/plan13_v48_evidence_graph_writer_live`
- Baseline root: `outputs/plan13_v47_direct_source_current_branch_live`
- Mode under test: `--report-writer-mode evidence-graph`
- Writer model observed: `deepseek-v4-pro`
- Material status: `skipped_evidence_graph_writer`
- Material agent bypassed: `true`

## Machine Checks

| Case | rc | validation | hard | soft | writer finish | LLM errors |
| -- | -- | -- | -- | -- | -- | -- |
| multi_host_confirmed_spread_plus | 0 | clean | 0 | 0 | stop | 20 |
| shared_infra_multi_asset_needs_review | 0 | clean | 0 | 0 | stop | 19 |
| suspected_exfil_after_execution | 0 | clean | 0 | 0 | stop | 18 |
| web_initial_access_to_beacon | 0 | clean | 0 | 0 | stop | 20 |
| web_initial_access_without_execution | 0 | clean | 0 | 0 | stop | 19 |

Compared with v47, v48 removes the `web_initial_access_to_beacon` hard-fail validator issue while keeping all five reports generated and validator-clean.

## Manual Rubric Notes

### Factual Grounding

Evidence-graph mode remains strongly grounded in deterministic source artifacts. Each graph-mode report preserved source-linked artifacts such as `report_evidence_graph.json`, `report_hypothesis_board.json`, and `report_graph_writer_brief.json`, which makes failure analysis easier than the direct-source path.

Residual concern: the investigation and reviewer layers produced repeated upstream LLM errors against the default `tool` / `chat` provider. The reports still completed because the pipeline recovered, but this live run should not be treated as a fully healthy investigation-layer run.

### Boundary Correctness

Evidence-graph mode generally improves boundary clarity. The tested reports consistently distinguish confirmed scope, candidate assets, shared infrastructure, background events, and open gaps. The shared-infrastructure case is especially clearer than a pure confirmation-style report because it holds the conclusion at "suspicious / needs review" rather than over-promoting weak shared-IP signals.

Residual concern: some wording still leans strong, for example "C2" or "beacon spread" in places where a more conservative "suspicious beacon-like communication" would be safer unless host-side execution is confirmed.

### Actionability

Actionability is at least tied with v47 and often better. Evidence-graph mode tends to name objects, data sources, and validation targets instead of giving generic "collect more host logs" advice. The multi-host report includes concrete follow-up around `rundll32.exe` command line, DLL hash/path, EDR process creation, and candidate asset validation.

Residual concern: appendix tables still include noisy external-reference domains as candidate indicators, which could distract operators from the core IOC / IOA set.

### Analytical Depth

Evidence-graph mode improves analytical depth in the complex and shared-infrastructure cases. The reports explain why repeated signals, shared infrastructure, maintenance windows, candidate expansion, and missing host telemetry change the final judgment instead of only replaying chronology.

Residual concern: some sections still sound generated, especially appendix evidence-card tables with repeated boundary language.

### Non-Repetition

Evidence-graph mode is reasonably non-repetitive in the main body: timeline, evidence judgment, scope, and limits mostly have distinct jobs. The appendix remains repetitive and should be treated as a technical artifact rather than polished prose.

### Operator Readability

Main bodies are readable for SOC / IR operators. The strongest improvement is the separation of confirmed assets from candidate and shared-infrastructure boundaries.

Residual concern: appendices are too noisy for executive or senior-review presentation without cleanup.

## Acceptance Recommendation

Evidence-graph mode passes the report-side experiment criteria:

- No new hard factual drift failures compared with v47.
- Boundary correctness improves or ties v47.
- It improves at least two dimensions: analytical depth, actionability, failure-analysis observability, and shared-infrastructure boundary handling.
- It does not rely on case-specific validator phrases.
- It produces useful graph and hypothesis artifacts for debugging.

Do not promote it as the default full pipeline yet. First fix or configure the investigation/reviewer model routing so live runs do not repeatedly hit upstream `tool` / `chat` provider errors. After that, rerun the same 5-case eval and repeat this comparison.


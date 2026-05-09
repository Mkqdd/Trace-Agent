# Incident Fixture Design

These fixtures are intended to test the incident investigation and report material pipeline as behavioral evals, not just parser smoke tests.

## Case Matrix

| Fixture | Target verdict | Main capability under test |
| --- | --- | --- |
| `multi_host_confirmed_spread_plus` | `confirmed_incident` | Multi-host beacon spread, lateral movement, candidate expansion, shared-infra boundary. |
| `shared_infra_multi_asset_needs_review` | `needs_review` | Shared infrastructure ambiguity, weak second-asset signal, false-positive/background handling, no over-expansion. |
| `suspected_exfil_after_execution` | `confirmed_incident` | Single-primary-asset execution to archive staging to outbound upload, exfil impact wording, candidate second asset. |
| `web_initial_access_to_beacon` | `confirmed_incident` | Web exploit to web-shell, host execution, C2, database-server expansion, candidate sibling web server. |
| `web_initial_access_without_execution` | `needs_review` | High-volume web/network signals without host-side corroboration; must not invent execution or lateral movement. |

## Design Rules

- Each non-trivial fixture should have enough events to exercise timeline routing, evidence judgment, relationship scope, and counterevidence limits.
- Complex fixtures should include confirmed/suspicious events, candidate scope, and background or counterevidence events.
- Candidate or shared-infrastructure objects must be reachable by seed pivots but should not automatically become confirmed affected assets.
- Negative/review fixtures must avoid stage keywords that accidentally trigger stronger stages, especially `execution`, `process`, `upload`, and `login` in event summaries.
- Acceptance should check verdict, asset roles, domains, stages, boundary phrases, and appendix coverage without overfitting to one generated paragraph.

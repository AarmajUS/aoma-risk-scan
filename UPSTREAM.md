# UPSTREAM.md — credit and license record

House rule: **credit loudly, own the layer.** This file records exactly what
the Aoma Risk Scan takes from upstream open-source projects, at what
versions, under what licenses — and the bright line between the upstream
engines and Aoma's original work.

## Upstream components

| Component | Version | License | Role in the scan |
|---|---|---|---|
| CodeGraphContext | 0.6.13 | MIT | Code map: function/call graph, cyclomatic complexity, dead code (`cgc index`, `cgc analyze`) |
| Gitleaks | 8.28.0 | MIT | Hardcoded-secret detection over the working tree |
| Semgrep | 1.182.1 | LGPL-2.1 | Pattern scanning. Run as an **external, unmodified tool** (not linked or embedded). Registry packs used: `p/python`, `p/secrets`, `p/security-audit`, plus Aoma's own rules |
| OSV-Scanner | 2.7.0 | Apache-2.0 | Dependency vulnerability matching against the OSV database |
| Semgrep registry rules | current at scan time | per-rule (registry terms) | Community pattern packs, credited by pack name in the report's method box |

## The bright line

- **Upstream's:** the graph extraction, the secret patterns, the registry
  SAST rules, the vulnerability database matching.
- **Aoma's (original, this repo):** `rules/aoma-python.yml` (formatted-SQL
  construction, hardcoded-secret assignments, debug-enabled, eval/exec —
  written after registry packs proved to miss those shapes), the Risk Score
  model and grade bands, the multi-engine orchestration in `scan.py`, the
  "say so when a check couldn't run" honesty behavior, and the report design.
- CGC draws the map; **our engine grades it.** No upstream project is
  presented as Aoma's work; every client report names each engine and its
  version so findings can be reproduced without us.

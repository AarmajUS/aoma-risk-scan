# Aoma Risk Scan — the engine behind the $299 AI Code Risk Scan

A **read-only** codebase scan: it maps a repository's structure, hunts for
secrets and dangerous patterns, checks pinned dependencies against known
vulnerabilities, and grades the result with the **Aoma Risk Score (/100)** in
a branded HTML report.

This is the working prototype (v0.1) of the scan sold through
[Aoma AI Agency](https://aomaai.com) — built to be verified, not believed.
The companion repo **[aoma-scan-demo](https://github.com/AarmajUS/aoma-scan-demo)**
is a tiny app with ten documented planted flaws; run this scanner on it and
check that every flaw shows up. Sample outputs live in `examples/`.

## House rule: credit loudly, own the layer

See `UPSTREAM.md` for the full credit/license record. In short:

- **Upstream engines (named in every report, on purpose):**
  CodeGraphContext (MIT) draws the code map — complexity outliers, dead code.
  Gitleaks (MIT) hunts hardcoded secrets. Semgrep (LGPL-2.1, run as an
  external tool) runs pattern packs. OSV-Scanner (Apache-2.0) matches
  dependencies to the OSV vulnerability database.
- **Aoma's layer (the original work in this repo):** the curated rule set
  (`rules/aoma-python.yml` — formatted-SQL construction, hardcoded-secret
  assignments, debug flags, eval/exec), the Risk Score model, the
  orchestration, and the report.

## Verified results (2026-10-25)

| Target | Findings | Score |
|---|---|---|
| aoma-scan-demo (10 planted flaw classes) | 61 — 1 secret, 8 pattern, 50 dependency vulns, complexity outliers, 4 dead functions | **11/100 (F)** |
| This repo (healthy control) | 2 complexity notes, 4 dead-code flags | **88/100 (B)** |

Every planted flaw class in the demo is caught. Where a check cannot run
(e.g. the vulnerability database is unreachable), the report says so in
plain language instead of silently claiming the code is clean.

## Run it

Prereqs (versions verified): Python 3.12, `codegraphcontext` 0.6.13 +
`semgrep` 1.182.1 (pip), `gitleaks` 8.28.0 and `osv-scanner` 2.7.0 (binaries).
Paths are configured at the top of `scan.py`.

```bash
python3 scan.py <repo_path> <output_report.html>
```

The scan only reads the target tree; it never writes to it.

## Honest limits (v0.1)

- Python-first: the curated rules target Python; JS/TS rules are future work.
- Graph metrics come from CodeGraphContext's CLI output; HTML files yield no
  function graph (source files are required for the map layer).
- Dependency findings include transitive packages (via OSV resolution) and
  are listed individually — grouping by package is a planned refinement.
- Score weights are v1 and under calibration; the report says so.

## Trust posture (how client code is handled)

Read-only by design · scan copies deleted on a written clock after delivery ·
no training on client code · every engine named in the report so any finding
can be reproduced independently.

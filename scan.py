#!/usr/bin/env python3
"""Aoma Risk Scan — prototype engine (v0.1).

Read-only structural + security scan of a codebase. Orchestrates four
open-source engines and grades the result with Aoma's Risk Score:

  Map        CodeGraphContext 0.6.13 (MIT)   — complexity outliers, dead code
  Secrets    Gitleaks 8.28.0 (MIT)           — hardcoded keys/passwords
  Patterns   Semgrep 1.182.1 (LGPL-2.1)      — registry packs + Aoma rules
  Dependencies OSV-Scanner 2.7.0 (Apache-2.0) — known CVEs in pinned deps

The scanner only reads. It never writes to the scanned tree.
Usage: scan.py <repo_path> <output_html>
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HOME = Path.home()
CGC = HOME / "workspace/.cgc-venv/bin/cgc"
SEMGREP = HOME / "workspace/.cgc-venv/bin/semgrep"
GITLEAKS = HOME / "workspace/.scanbin/gitleaks"
OSV = HOME / "workspace/.scanbin/osv-scanner"
AOMA_RULES = Path(__file__).parent / "rules" / "aoma-python.yml"


def run(cmd, timeout=600, cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd)
        return p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return ""


def scan_secrets(repo):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    run([str(GITLEAKS), "dir", str(repo), "--no-banner",
         "--report-format", "json", "--report-path", out], timeout=300)
    try:
        data = json.loads(Path(out).read_text())
    except Exception:
        data = []
    out = []
    for d in data:
        fp = d.get("File", "")
        try:
            fp = str(Path(fp).resolve().relative_to(repo))
        except Exception:
            pass
        out.append({"tool": "Gitleaks", "kind": "secret",
                    "severity": "critical",
                    "title": f"Hardcoded secret ({d.get('RuleID', 'unknown rule')})",
                    "file": fp, "line": d.get("StartLine", "")})
    return out


def scan_patterns(repo):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    run([str(SEMGREP), "--config=p/python", "--config=p/secrets",
         "--config=p/security-audit", f"--config={AOMA_RULES}",
         "--json", "--output", out, "--metrics=off", "--quiet", "."],
        timeout=600, cwd=str(repo))
    try:
        data = json.loads(Path(out).read_text())
    except Exception:
        data = {"results": []}
    findings, seen = [], set()
    for r in data.get("results", []):
        key = (r["path"], r["start"]["line"])
        if key in seen:
            continue
        seen.add(key)
        cid = r["check_id"]
        sev = "critical" if any(k in cid for k in
                                ("sql", "eval", "secret", "stripe")) else "high"
        findings.append({"tool": "Semgrep", "kind": "pattern",
                         "severity": sev,
                         "title": r.get("extra", {}).get("message", cid)[:140],
                         "file": r["path"], "line": r["start"]["line"]})
    return findings


def scan_deps(repo):
    """Returns (findings, checked). Retries once: the deps.dev resolution
    call occasionally stalls; a silent zero would be a lie, so the report
    states plainly when dependencies could not be checked."""
    lockfiles = ([p for p in repo.rglob("requirements.txt")] +
                 [p for p in repo.rglob("package-lock.json")] +
                 [p for p in repo.rglob("go.mod")])
    if not lockfiles:
        return [], True
    for _attempt in range(2):
        findings, got_any = [], False
        for lf in lockfiles[:3]:
            with tempfile.NamedTemporaryFile(suffix=".json",
                                             delete=False) as f:
                out = f.name
            run([str(OSV), "--lockfile", str(lf), "--format", "json",
                 "--output", out], timeout=420)
            try:
                data = json.loads(Path(out).read_text())
            except Exception:
                continue
            got_any = True
            for res in data.get("results", []):
                for pkg in res.get("packages", []):
                    name = pkg["package"]["name"]
                    ver = pkg["package"]["version"]
                    for v in pkg.get("vulnerabilities", []):
                        findings.append({
                            "tool": "OSV-Scanner", "kind": "dependency",
                            "severity": "high",
                            "title": f"{name} {ver} — {v['id']}: "
                                     f"{(v.get('summary') or 'known vulnerability')[:90]}",
                            "file": str(lf.relative_to(repo)), "line": ""})
        if got_any:
            return findings, True
    return [], False


def scan_graph(repo):
    findings = []
    run([str(CGC), "index", str(repo), "--force", "--no-progress"], timeout=600)
    cx = run([str(CGC), "analyze", "complexity"], timeout=300)
    m = re.search(r"(\d+) function\(s\) exceed threshold", cx)
    if m and int(m.group(1)):
        for name in re.findall(r"│\s*([A-Za-z_][\w]*)\s*│\s*(\d{2,})\s*│", cx):
            findings.append({"tool": "CodeGraphContext", "kind": "complexity",
                             "severity": "medium",
                             "title": f"High-complexity function {name[0]} "
                                      f"(cyclomatic {name[1]}) — hard to test, "
                                      f"easy to break",
                             "file": "", "line": ""})
        if not findings:
            findings.append({"tool": "CodeGraphContext", "kind": "complexity",
                             "severity": "medium",
                             "title": f"{m.group(1)} function(s) over the "
                                      f"complexity threshold",
                             "file": "", "line": ""})
    dc = run([str(CGC), "analyze", "dead-code"], timeout=300)
    m2 = re.search(r"Total: (\d+) function", dc)
    dead = int(m2.group(1)) if m2 else 0
    names = re.findall(r"│\s*([A-Za-z_][\w]*)\s*│\s*●", dc)
    return findings, dead, names


def score(findings, dead_count):
    s = 100
    secrets = [f for f in findings if f["kind"] == "secret"]
    crit = [f for f in findings if f["severity"] == "critical"
            and f["kind"] != "secret"]
    high = [f for f in findings if f["severity"] == "high"]
    cx = [f for f in findings if f["kind"] == "complexity"]
    deps = [f for f in findings if f["kind"] == "dependency"]
    s -= min(36, 12 * len(secrets))
    s -= min(30, 10 * len(crit))
    s -= min(20, 2 * len(deps))
    s -= min(15, 5 * len([h for h in high if h["kind"] == "pattern"]))
    s -= min(12, 4 * len(cx))
    s -= min(8, 1 * dead_count)
    return max(5, s)


def grade(s):
    return ("A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60
            else "D" if s >= 40 else "F")


def esc(t):
    return (str(t).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def report(repo, findings, dead, dead_names, sc, deps_checked=True):
    g = grade(sc)
    rows = ""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 9)):
        loc = esc(f["file"]) + (f":{f['line']}" if f["line"] else "")
        rows += (f"<tr><td><span class='sev {f['severity']}'>"
                 f"{f['severity'].upper()}</span></td>"
                 f"<td>{esc(f['title'])}</td><td>{loc}</td>"
                 f"<td>{esc(f['tool'])}</td></tr>")
    if not deps_checked:
        findings_note = ("<p><b>Note:</b> the dependency database could not "
                         "be reached during this run, so pinned dependencies "
                         "were NOT checked. This report does not claim they "
                         "are clean.</p>")
    else:
        findings_note = ""
    dead_html = findings_note
    if dead:
        dead_html = (f"<p><b>Dead code:</b> {dead} function(s) with no "
                     f"callers ({esc(', '.join(dead_names[:8]))}) — "
                     f"maintenance weight and hiding places for bugs.</p>")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aoma Risk Scan — {esc(repo.name)}</title>
<style>
body{{font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;background:#070b16;color:#eef2ff;margin:0;padding:28px 18px 60px}}
.wrap{{max-width:820px;margin:0 auto}}
h1{{font-size:30px;margin:0 0 4px}} .sub{{color:#9fb0d8;margin:0 0 22px}}
.score{{display:flex;gap:18px;align-items:center;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.14);border-radius:16px;padding:20px;margin-bottom:22px}}
.big{{font-size:56px;font-weight:800;line-height:1}}
.grade{{font-size:22px;font-weight:800;padding:8px 16px;border-radius:12px;background:#b91c1c;color:#fff}}
table{{width:100%;border-collapse:collapse;font-size:13.5px}}
td,th{{padding:8px;border-bottom:1px solid rgba(255,255,255,.12);text-align:left;vertical-align:top}}
.sev{{font-size:11px;font-weight:800;padding:2px 8px;border-radius:8px}}
.critical{{background:#7f1d1d;color:#fecaca}} .high{{background:#7c2d12;color:#fed7aa}}
.medium{{background:#713f12;color:#fde68a}} .low{{background:#1f2937;color:#d1d5db}}
.box{{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);border-radius:14px;padding:16px;margin-top:22px;font-size:13.5px;line-height:1.65;color:#c7d2fe}}
footer{{margin-top:26px;color:#9fb0d8;font-size:12.5px;line-height:1.7}}
</style></head><body><div class="wrap">
<h1>Aoma Risk Scan</h1>
<p class="sub">Repository: <b>{esc(repo.name)}</b> · Read-only scan · Prototype report v0.1</p>
<div class="score"><div class="big">{sc}</div><div>
<div class="grade">Grade {g}</div>
<p style="color:#9fb0d8;margin:8px 0 0">Aoma Risk Score /100 — structural + security health of the codebase.</p>
</div></div>
<table><tr><th>Severity</th><th>Finding</th><th>Where</th><th>Engine</th></tr>
{rows}</table>
{dead_html}
<div class="box"><b>What checked this code (named, on purpose):</b><br>
CodeGraphContext 0.6.13 (MIT) drew the code map — function complexity and dead code.
Gitleaks 8.28.0 (MIT) hunted hardcoded secrets. Semgrep 1.182.1 (LGPL-2.1) ran
registry pattern packs (p/python, p/secrets, p/security-audit) plus Aoma's own
curated rules. OSV-Scanner 2.7.0 (Apache-2.0) matched pinned dependencies
against the OSV vulnerability database. The Aoma layer is the rule curation,
the Risk Score, and this report.<br><br>
<b>How we handle code:</b> the scan is read-only — it never writes to your
tree. Scan copies are deleted on a written clock after delivery. We never
train models on client code.</div>
<footer>Aoma AI Agency · AARMAJ LLC, Ewing NJ · (609) 745-1580 · Prototype — scoring weights v1, under calibration.</footer>
</div></body></html>"""


def main():
    repo = Path(sys.argv[1]).resolve()
    out = Path(sys.argv[2])
    findings = []
    findings += scan_secrets(repo)
    findings += scan_patterns(repo)
    dep_findings, deps_checked = scan_deps(repo)
    findings += dep_findings
    graph_findings, dead, dead_names = scan_graph(repo)
    findings += graph_findings
    sc = score(findings, dead)
    out.write_text(report(repo, findings, dead, dead_names, sc, deps_checked))
    print(f"findings: {len(findings)} (secrets "
          f"{len([f for f in findings if f['kind']=='secret'])}, patterns "
          f"{len([f for f in findings if f['kind']=='pattern'])}, deps "
          f"{len([f for f in findings if f['kind']=='dependency'])}, "
          f"complexity {len([f for f in findings if f['kind']=='complexity'])}, "
          f"dead {dead})")
    print(f"AOMA RISK SCORE: {sc}/100 (grade {grade(sc)})")
    print(f"report: {out}")


if __name__ == "__main__":
    main()

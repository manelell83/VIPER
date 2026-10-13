# Contributions — V.I.P.E.R.

## Project context
V.I.P.E.R. is a network vulnerability analysis and risk‑prioritization tool,
originally built as a team academic project at INPT (cybersecurity engineering
program). This document describes my contribution, with a focus on the **v2**
work that made every capability run on real data.

## How to read this repository
The whole tool — and the way I worked on it — follows one loop:
**find → assess → resolve**. The product applies it to vulnerabilities; the
self‑audit (below) applies it to the codebase itself. The complete v2 is
captured as a single reviewable diff in **Pull Request #1**, with a structured
summary of the eight phases.

## My focus — evidence‑based, risk‑based prioritization
VIPER's pipeline is **find → assess → resolve**, and my focus is the
**assess → prioritize → resolve** stages: turning detected services and their
CVEs into a defensible, ranked list of what to fix first.

- **Assess (real evidence, not just CVSS).** CVEs are matched by **CPE**
  (product + version) and clearly separated from weaker keyword matches
  (possible false positives). Each is enriched with **CISA KEV**
  (exploited in the wild) and **EPSS** (exploitation probability), and exploit
  maturity is backed by real references (Exploit‑DB / Metasploit) — never
  guessed from CVSS. "Exploited in the world" is kept distinct from
  "confirmed vulnerable here".
- **Prioritize (transparent, human‑in‑control).** A deterministic 0–100 score
  with a **visible factor breakdown** (exploitation evidence, EPSS, CVSS,
  match confidence, host exposure, lateral movement). An optional LLM layer
  only *explains* the computed result — it never changes a score — and the
  analyst keeps control (reorder / dismiss).
- **Resolve.** Per‑finding remediation, safe **non‑destructive** verification
  guidance (human‑in‑the‑loop — the tool never runs exploits), and a
  professional PDF audit report (executive summary → methodology →
  prioritized findings → attack paths → remediation).

Evidence‑based **attack paths** (reachability / exploitability / impact, with
MITRE ATT&CK references) support this, and are presented honestly as a
heuristic model — not a formal attack graph.

## Security self‑audit & hardening — find → assess → resolve on the codebase
A concrete find → assess → resolve exercise applied to the project itself:

| Found | Assessed | Resolved |
|---|---|---|
| No authentication on API routes | Critical — full data/control exposure | JWT enforced on every route; admin/analyst roles |
| Nmap argument injection | High — arbitrary file write verified (no code execution demonstrated) | Input validated; option injection blocked (verified) |
| Default / hardcoded secrets | High | Removed; secrets via environment only |
| Inflated, unverifiable claims in the docs | Integrity issue | Docs rewritten honestly, with a "Known limitations" section |
| Broken Docker build | Blocks deployment | Secure, working docker‑compose (non‑root, loopback‑only, no secret in image) |
| App did not start; no real test safety net | Unmaintainable | **436 tests**, green CI on Python 3.11 & 3.13 |

## Engineering discipline
Real data only (no simulated results); an explicit **"Known limitations"**
section throughout; automated tests with CI across two Python versions; secure
containerization; and a consistent separation between what is **confirmed** and
what is **heuristic**.

## Tooling transparency
The v2 was built **under my direction, review and lab validation** (verified on
a real Metasploitable lab), with the help of AI coding tools — visible in the
commit history. The engineering decisions, the security requirements and the
honesty‑first methodology are mine.

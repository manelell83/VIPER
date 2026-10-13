# Contributions — V.I.P.E.R.

## Project context
V.I.P.E.R. is a network vulnerability analysis and risk-prioritization
tool, originally built as a team academic project at INPT (cybersecurity
engineering program).

## What this repository demonstrates
Both the tool and my recent work on it follow the same loop:
**find → assess → resolve**. The product applies it to vulnerabilities;
I applied it to the codebase itself.

## My focus — Risk-based vulnerability prioritization
VIPER's pipeline is **find → assess → resolve**. My focus was the
**assess and resolve** stages — the logic that turns detected services
and their CVEs into a ranked list of remediation priorities
(risk_engine.py, risk_classifier.py, remediation_engine.py):
- **Assess:** score and rank each vulnerability by CVSS, plus an
  exploit-maturity heuristic (indicative labels derived from CVSS and a
  small curated set of well-known CVEs)
- **Resolve:** produce a prioritized remediation order

The upstream **find** stage — service discovery and CVE correlation
against the NVD API (service_parser.py, cve_lookup.py) — feeds this
logic.

## Security audit & hardening — individual work (verifiable in git history)
A concrete find → assess → resolve exercise on a real codebase:

| Found | Assessed | Resolved |
|---|---|---|
| No authentication on API routes | Critical — full data/control exposure | JWT enforced on every route |
| Nmap argument injection | High — arbitrary file write verified (no code execution demonstrated) | Input validated; option injection blocked (verified) |
| Default / hardcoded secrets | High | Removed; secrets via environment only |
| Inflated, unverifiable claims in the docs | Integrity issue | Docs rewritten honestly, with a "Known limitations" section |
| Broken Docker build | Blocks deployment | Secure, working docker-compose (non-root, loopback-only, no secret in image) |
| App did not start; test suite could not run (29% coverage once patched) | No real test safety net | 247 tests, 68.5% coverage, green CI on Python 3.11 & 3.13 |

## Engineering practices
Automated tests, CI across two Python versions, secure containerization,
and documentation that states what works and what doesn't.

## Tooling transparency
This project was developed with the help of AI coding tools (visible in
the commit history), under my own direction, review and testing.

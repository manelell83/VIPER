# V.I.P.E.R.

A network vulnerability analysis tool that discovers exposed services, correlates them with known CVEs and prioritises them by risk.

V.I.P.E.R. (the application calls itself *ViperV2*) is an **academic project** (PFA, cybersecurity engineering, 2025–2026). It was built for learning and for use in lab environments. It is not a hardened product.

> Only scan systems you own or are explicitly authorised to test. `scanme.nmap.org` is provided by the Nmap project for testing.

---

## What works

Each item below was checked in an end-to-end run against a real target (`127.0.0.1`), going through the frontend's proxy the way a browser does.

- **JWT authentication on every route.** Only `/auth/login`, `/health` and `/` are public. Requests without a valid token get `401`. There are two roles: `admin` (can create users and delete scans) and `analyst`.
- **Port and service scanning with Nmap**, with service and version detection.
- **CVE correlation** through the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities): CPE matching when the product/version is known (flagged *Confirmed*), keyword fallback otherwise (*Weak match*). Each CVE is enriched with its **CISA KEV** flag (exploited in the wild) and **EPSS** score, with per-host and network risk scores.
- **AI Prioritization (deterministic core + optional LLM).** Findings ranked most-urgent first by a transparent 0-100 score from real signals, with a full factor breakdown per finding and human-in-the-loop overrides. An optional LLM (key via environment, template fallback) writes plain-language explanations only — it never changes a score.
- **Exploitability intelligence (no exploitation).** Per-CVE maturity from real evidence — CISA KEV, public exploit references (Exploit-DB, Metasploit module names, NVD "Exploit" tags) and EPSS — with safe, human-in-the-loop verification steps. References are links, never exploit code.
- **Passive domain recon.** DNS records, RDAP/WHOIS (with a python-whois fallback), subdomains from Certificate Transparency (crt.sh) and a light web fingerprint, linked into a domain → subdomain → IP → service graph. No active scanning.
- **Evidence-based attack paths** built with NetworkX: each path is scored on three transparent components — reachability, hop exploitability (reusing KEV/EPSS/CPE evidence) and impact — with a per-path justification and optional MITRE ATT&CK references.
- **Real-time updates over WebSocket.** The socket authenticates with the JWT in its first message.
- **JSON and PDF reports** (the PDF is generated with ReportLab).
- **FastAPI backend and React frontend.**

LAN discovery (ARP with Scapy, plus a ping-sweep fallback) is implemented, but it was **not** part of the end-to-end check above.

## Tech stack

| Layer | Technologies |
|---|---|
| Backend | Python, FastAPI, SQLAlchemy, SQLite |
| Scanning | Nmap (python-nmap), Scapy |
| Analysis | NVD API (httpx), NetworkX |
| Auth | JWT (PyJWT, HS256), bcrypt |
| Real time | WebSocket |
| Frontend | React, Vite, Tailwind CSS, Cytoscape.js |

## Quality

- **247 automated tests** (pytest), covering the API, authentication and roles, input validation, risk scoring, NVD parsing, Nmap result parsing and attack-path generation.
- **68.5 % line coverage** of the backend.
- **GitHub Actions CI** runs the tests on Python 3.11 and 3.13 and builds the frontend.

```bash
cd backend
pip install -r requirements-dev.txt
pytest --cov=app
```

---

## Running with Docker

Requires Docker with Docker Compose.

```bash
cp backend/.env.example backend/.env     # then set JWT_SECRET (see below)
docker compose up -d --build
docker compose exec backend python -m app.create_admin --username admin --email admin@example.com
```

Open http://localhost:3000. nginx serves the frontend and forwards `/api` and `/ws` to the backend. Both ports are bound to `127.0.0.1` only. The SQLite database is kept in the `viperv2-db` volume, and `backend/.env` is never copied into the image. Stop the stack with `docker compose down`.

## Installation and running (local)

Tested on Windows 11. On Linux and macOS the commands are the same, apart from how you activate the virtual environment.

### Prerequisites

- Python 3.11+
- Node.js 20+
- [Nmap](https://nmap.org/download.html), available on the `PATH`
- Optional, for LAN discovery: administrator/root rights, and [Npcap](https://npcap.com/) on Windows
- Optional: an NVD API key. It's free from [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) and raises the NVD rate limit from 5 to 50 requests per 30 s.

### 1. Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate            # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env              # Windows cmd: copy .env.example .env
```

Edit `backend/.env` and set `JWT_SECRET` (required, 32 characters or more; the backend refuses to start without it). You can generate one with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

If you have an NVD key, add it as `NVD_API_KEY`.

Create the first admin account. There is no public sign-up: the admin creates the other users through `POST /auth/users`.

```bash
python -m app.create_admin --username admin --email admin@example.com
```

The password is prompted for and must be at least 10 characters.

Start the API:

```bash
python -m uvicorn app.main:app --port 8001
```

The interactive API docs are at http://localhost:8001/docs.

### 2. Frontend

In a second terminal:

```bash
cd frontend
npm ci
npm run dev
```

Open http://localhost:5173 and sign in. The Vite dev server forwards `/api` and `/ws` to the backend on port 8001.

---

## Known limitations

- **CVE correlation: CPE reduces false positives but does not eliminate them.** When Nmap identifies a product and version, CVEs are matched by CPE (for example `cpe:2.3:a:apache:http_server:2.2.8`) and shown as **Confirmed**. When the product or version is unknown (e.g. an unversioned "Microsoft Windows RPC" banner), a keyword search is used and the results are flagged **Weak match** — these may be false positives. So some noise remains for services VIPER cannot identify precisely; always check a weak match before acting on it.
- **"Exploited in the world" is not "vulnerable here".** Each CVE carries a **CISA KEV** flag (confirmed exploited in the wild) and an **EPSS** score (exploitation probability) — both **real data**, not a heuristic. They describe the CVE globally, not whether a given host is actually vulnerable: a weak-match CVE can have a high EPSS and still be a false positive (e.g. the Windows RPC CVE-2003-0352 shows EPSS 0.98 on a modern host where it does not apply). The UI keeps these separate from the Confirmed/Weak match label.
- **The attack graph is a heuristic, evidence-based model — not a formal attack graph.** Unlike a logic-based tool (e.g. MulVAL), it does not *prove* reachability or chain exploit preconditions; it ranks *plausible* paths from the real scan evidence so an analyst can review them. Each hop is scored on reachability (from the discovered hosts/subnets/open ports), exploitability (reusing the Phase-4 evidence — CISA KEV, EPSS, CPE-confirmed match, exploit maturity, CVSS) and impact/gain, combined transparently (0.20·R + 0.50·E + 0.30·I) with a visible breakdown and a plain-language justification per path. Reachability on a single flat subnet is assumed from open ports, not verified by live traversal. Treat the paths as leads, not proof.
- **AI Prioritization is a decision aid, not a verdict.** The ranking and the 0-100 score are produced by a transparent, deterministic engine from real signals (exploitation evidence, EPSS, CVSS, match confidence, host exposure, lateral movement) — every finding shows its full factor breakdown. The optional LLM layer (provider and key from the environment, never hardcoded; falls back to deterministic templates when no key) only **explains** the computed data in plain language — it invents no scores and does not change the ranking, and AI-written text is labelled as such. The analyst stays in the loop (pin/dismiss/reorder). Treat the order as a prioritised to-do list to validate, not an absolute truth.
- **Exploitability is intelligence only, and its maturity is now evidence-based.** `WEAPONIZED` / `FUNCTIONAL` / `POC` come from real evidence — CISA KEV (exploited in the wild), public exploit references (Exploit-DB, Metasploit module names, NVD references tagged "Exploit") and EPSS — **not** inferred from CVSS. When no such evidence exists the maturity is reported as `UNKNOWN`, not guessed. **Absence of a public exploit is not absence of risk:** a CVE with no known exploit can still be exploitable, so `UNKNOWN` means "no evidence found", not "safe". Exploit references are links to public databases, never exploit code; VIPER performs no exploitation and offers only safe, non-destructive manual-verification steps (banner/version checks on an authorised target).
- **WebSocket progress is incomplete.** The first events of a scan can be missed if the client connects after the scan has started, because events are not replayed. No progress events are sent during the Nmap phase (about 20 s). This is a design limitation.
- **In Docker, LAN discovery and OS detection are not available.** The backend container sits on Docker's internal network and runs as an unprivileged user. Scans of an IP address or hostname work, but ARP discovery of the host's real LAN does not, and Nmap OS detection (`-O`, which needs root) is skipped. For LAN scans, run the backend locally.
- **npm audit reports 7 advisories** (rated moderate and high) in the build-time tooling of Tailwind CSS 3 (`braces`, `micromatch`, `postcss-selector-parser`). They don't affect the code that ships to the browser: `npm audit --omit=dev` reports 0 vulnerabilities. Fixing them requires migrating to Tailwind 4.

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
- **Attack-path graph** built with NetworkX, from an "external attacker" node through entry points and lateral movement.
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
- **The Exploitability page still uses a maturity heuristic.** Its `WEAPONIZED` / `FUNCTIONAL` / `POC` labels are inferred from CVSS plus a small curated CVE table, superseded by the real KEV/EPSS signals above; reconciling that page with KEV/EPSS is planned for a later phase.
- **WebSocket progress is incomplete.** The first events of a scan can be missed if the client connects after the scan has started, because events are not replayed. No progress events are sent during the Nmap phase (about 20 s). This is a design limitation.
- **In Docker, LAN discovery and OS detection are not available.** The backend container sits on Docker's internal network and runs as an unprivileged user. Scans of an IP address or hostname work, but ARP discovery of the host's real LAN does not, and Nmap OS detection (`-O`, which needs root) is skipped. For LAN scans, run the backend locally.
- **npm audit reports 7 advisories** (rated moderate and high) in the build-time tooling of Tailwind CSS 3 (`braces`, `micromatch`, `postcss-selector-parser`). They don't affect the code that ships to the browser: `npm audit --omit=dev` reports 0 vulnerabilities. Fixing them requires migrating to Tailwind 4.

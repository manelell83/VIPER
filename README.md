# V.I.P.E.R.

A network vulnerability analysis tool that discovers exposed services, correlates them with known CVEs and prioritises them by risk.

V.I.P.E.R. (the application calls itself *ViperV2*) is an **academic project** (PFA, cybersecurity engineering, 2025–2026). It was built for learning and for use in lab environments. It is not a hardened product.

> Only scan systems you own or are explicitly authorised to test. `scanme.nmap.org` is provided by the Nmap project for testing.

---

## What works

Each item below was checked in an end-to-end run against a real target (`127.0.0.1`), going through the frontend's proxy the way a browser does.

- **JWT authentication on every route.** Only `/auth/login`, `/health` and `/` are public. Requests without a valid token get `401`. There are two roles: `admin` (can create users and delete scans) and `analyst`.
- **Port and service scanning with Nmap**, with service and version detection.
- **CVE correlation** through the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities), with per-host and network risk scores.
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

- **CVE correlation is keyword-based.** Services are matched to CVEs through NVD keyword searches (for example `openbsd openssh 8.2`), not through strict CPE matching. This produces false positives: in testing, old Windows RPC CVEs (2000–2004) were reported against a modern Windows 11 host. Treat the results as leads to investigate, not confirmed vulnerabilities.
- **Exploit maturity is a heuristic.** Labels such as `WEAPONIZED`, `FUNCTIONAL` or `POC` don't come from a real exploit data source (for example EPSS, CISA KEV or Exploit-DB). For 26 well-known CVEs (EternalBlue, BlueKeep, …) the label comes from a hard-coded table. For every other CVE it is inferred from the CVSS score and vector. Treat it as an indication only.
- **WebSocket progress is incomplete.** The first events of a scan can be missed if the client connects after the scan has started, because events are not replayed. No progress events are sent during the Nmap phase (about 20 s). This is a design limitation.
- **Docker images do not build yet.** The Dockerfiles and `docker-compose.yml` are in the repository but don't currently work. Run the application locally as described above.
- **npm audit reports 7 advisories** (rated moderate and high) in the build-time tooling of Tailwind CSS 3 (`braces`, `micromatch`, `postcss-selector-parser`). They don't affect the code that ships to the browser: `npm audit --omit=dev` reports 0 vulnerabilities. Fixing them requires migrating to Tailwind 4.
- **`datetime.utcnow()` deprecation warnings** still need to be replaced with timezone-aware datetimes.

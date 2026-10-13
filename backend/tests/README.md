# Backend test suite

**247 tests**, **68.5 % line coverage** of `app/`. Measured with pytest on Python 3.11 and 3.13 (the two CI versions).

The tests run offline. Nmap, DNS and the NVD API are replaced by fakes. The only network activity is one test that opens a listening socket on `127.0.0.1`.

## Running

From the `backend/` directory:

```bash
pip install -r requirements-dev.txt

pytest                      # whole suite
pytest tests/api/test_auth.py               # one file
pytest tests/api/test_auth.py::TestLogin    # one class
pytest --cov=app --cov-report=term          # with coverage
```

`conftest.py` sets `DATABASE_URL` (in-memory SQLite) and a test-only `JWT_SECRET` before the app is imported. The tests therefore don't need a `.env` file and never create `viperv2.db`.

## Layout

The counts include each case of a parametrized test.

```
tests/
├── conftest.py                       shared fixtures (see below)
├── test_config.py                (3)   settings: no default JWT secret, bounds
├── test_database.py             (10)   sessions, cascades, foreign keys
├── test_models.py               (11)   ORM models and serialization
├── api/
│   ├── test_auth.py             (56)   401 on every protected route, login,
│   │                                   token validation, roles, WebSocket auth
│   ├── test_scan.py             (28)   scan requests, target validation /
│   │                                   nmap option injection, scan status
│   ├── test_vulnerabilities.py   (9)   filters, per-host risk, risk summary
│   ├── test_attack_graph.py      (4)   on-demand graph, regeneration, multi-scan
│   └── test_reports.py           (3)   JSON / PDF export, markup in scanned data
├── scanners/
│   ├── test_port_scanner.py     (13)   nmap result parsing, socket fallback,
│   │                                   refusal of non-IPv4 targets
│   ├── test_network_calculator.py (22) hostname rules, DNS resolution errors
│   └── test_scan_engine.py       (3)   domain-scan pipeline, error messages
├── vulnerability_scanner/
│   ├── test_risk_engine.py      (21)   host / network risk formulas
│   ├── test_service_parser.py   (16)   nmap service -> NVD query
│   └── test_cve_lookup.py       (21)   NVD response parsing, cache, API key
└── attack_graph/
    ├── test_attack_rules.py     (11)   rule matching, CVSS boost, port linking
    └── test_graph_and_paths.py  (16)   graph construction, path scores
```

## Fixtures

Shared fixtures, defined in `conftest.py`:

| Fixture | Provides |
|---|---|
| `test_db` | A fresh in-memory SQLite session for each test. It uses `StaticPool`, so the TestClient thread sees the same database. |
| `client` | A `TestClient` authenticated as an `analyst` user. |
| `admin_client` | A `TestClient` authenticated as an `admin` user. |
| `anon_client` | A `TestClient` with no token. |
| `make_client(role)` | The factory behind the three clients above. |

`conftest.py` also provides a helper function (not a fixture), `create_user(db, username, role, is_active=True)`, which creates a user whose password is `TEST_PASSWORD`.

Fixtures local to a single file:

| File | Fixtures |
|---|---|
| `api/test_scan.py` | `scheduled`: replaces the background scan jobs and the interface lookup, and records the calls. |
| `api/test_vulnerabilities.py` | `scan_with_vulns` |
| `attack_graph/test_graph_and_paths.py` | `scan`: three hosts (ssh, winrm, unknown port). |
| `scanners/test_scan_engine.py` | `events`, `domain_scan`, `no_cve_lookup` |
| `test_models.py` | `scan_session`, `host_with_scan`, `scan_with_graph` |
| `vulnerability_scanner/test_cve_lookup.py` | `empty_cache`, `fake_nvd`, `no_delay` |

Async tests are plain `async def` functions. `pytest.ini` sets `asyncio_mode = auto`, so they need no marker.

## CI

`.github/workflows/test.yml` runs the following on every push and on pull requests to `main`:

- flake8 (syntax errors and undefined names only)
- pytest with coverage on Python 3.11 and 3.13. The run fails below **50 %** coverage, a threshold set under the current figure to catch regressions.
- `npm ci && npm run build` for the frontend

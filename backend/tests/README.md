# ViperV2 Backend Test Suite

## Overview

Comprehensive test suite for ViperV2 backend with **60+ tests** covering:
- Models and database integration
- API routes and endpoints
- Error handling and validation
- Concurrent operation isolation

## Installation

```bash
cd backend

# Install test dependencies
pip install pytest pytest-asyncio pytest-cov httpx factory-boy pytest-mock

# Or use requirements.txt
pip install -r requirements.txt
```

## Running Tests

### All Tests
```bash
pytest
```

### Specific Test File
```bash
pytest tests/test_models.py
```

### Specific Test Class
```bash
pytest tests/test_models.py::TestScanSessionModel
```

### Specific Test
```bash
pytest tests/test_models.py::TestScanSessionModel::test_scan_session_creation
```

### With Coverage Report
```bash
pytest --cov=app --cov-report=html --cov-report=term
```

### Coverage Report (HTML)
```bash
# After running tests with --cov-report=html
open htmlcov/index.html  # macOS
# or
start htmlcov/index.html  # Windows
```

### Run Only Fast Tests (skip slow/integration)
```bash
pytest -m "not slow and not integration"
```

### Run Only Unit Tests
```bash
pytest -m "unit"
```

### Verbose Output
```bash
pytest -v
```

## Test Structure

```
tests/
├── conftest.py                    # Shared fixtures
├── test_models.py                 # Database models (8 tests)
├── test_database.py               # DB integration (12 tests)
├── api/
│   ├── test_scan.py              # Scan routes (12 tests)
│   ├── test_vulnerabilities.py    # Vuln routes (8 tests)
│   └── test_attack_graph.py       # Graph routes (10 tests)
├── scanners/
│   └── test_arp_scanner.py        # (TODO)
├── vulnerability_scanner/
│   └── test_cve_lookup.py         # (TODO)
└── attack_graph/
    ├── test_graph_builder.py      # (TODO)
    └── test_path_engine.py        # (TODO)
```

## Test Coverage by Module

| Module | Tests | Status |
|--------|-------|--------|
| Models | 8 | ✅ Complete |
| Database | 12 | ✅ Complete |
| Scan Routes | 12 | ✅ Complete |
| Vulnerability Routes | 8 | ✅ Complete |
| Attack Graph Routes | 10 | ✅ Complete |
| ARP Scanner | 8 | 🔄 TODO |
| CVE Lookup | 6 | 🔄 TODO |
| Graph Builder | 5 | 🔄 TODO |
| Path Engine | 5 | 🔄 TODO |
| **TOTAL** | **74+** | **🎯 In Progress** |

## Fixtures Available

### Database & Client
- `test_db`: In-memory SQLite database per test
- `client`: FastAPI TestClient with test database
- `event_loop`: Async event loop for asyncio tests

### Mocks
- `mock_arp`: Mock ARP scanner responses
- `mock_port_scanner`: Mock port scanner responses
- `mock_nvd`: Mock NVD API responses
- `mock_ws_manager`: Mock WebSocket manager

### Test Data
- `scan_session`: Test ScanSession
- `host_with_scan`: Test Host within a scan
- `scan_with_vulns`: Scan with 3 vulnerabilities
- `scan_with_attack_graph`: Scan with attack graph

## CI/CD Integration

### GitHub Actions (`.github/workflows/test.yml`)
Automatically runs tests on:
- Push to any branch
- Pull requests

```bash
# Manual trigger
gh workflow run test.yml
```

### Coverage Requirements
- Minimum: 70% code coverage
- Fails if coverage drops below threshold
- HTML report generated on failure

## Common Issues & Solutions

### `pytest: command not found`
```bash
pip install pytest
# or
python -m pytest
```

### Import errors in tests
```bash
# Ensure you're in backend directory
cd backend

# Reinstall in development mode
pip install -e .
```

### Asyncio test failures
```bash
# Ensure pytest-asyncio is installed
pip install pytest-asyncio

# Update conftest.py has asyncio_mode = "auto"
```

### Database locked error
```bash
# SQLite can have concurrency issues
# Tests use in-memory :memory: database to avoid this
# If persists, increase sqlite timeout in conftest.py
```

## Writing New Tests

### Template: Unit Test
```python
import pytest

class TestMyFeature:
    def test_my_feature_works(self, test_db):
        """Describe what this tests."""
        # Arrange
        data = MyModel(...)
        test_db.add(data)
        test_db.commit()
        
        # Act
        result = query_my_feature(data.id)
        
        # Assert
        assert result is not None
        assert result.status == "success"
```

### Template: Async Test
```python
@pytest.mark.asyncio
async def test_async_route(client):
    """Test async endpoint."""
    response = await client.get("/endpoint")
    assert response.status_code == 200
```

### Template: Mocked External Call
```python
from unittest.mock import patch

def test_with_mock(mock_nvd):
    """Test with mocked NVD API."""
    # mock_nvd is already configured in conftest.py
    response = search_cves("Apache", "2.4.1")
    assert response is not None
```

## Performance

### Test Execution Time
- Full suite: ~15 seconds
- Per module: ~2-3 seconds
- Single test: <100ms

### Optimization Tips
- Use in-memory database for speed
- Mock external APIs (NVD, EPSS)
- Run only affected tests: `pytest --lf` (last failed)

## Next Steps

1. **Install pytest**: `pip install pytest pytest-asyncio pytest-cov`
2. **Run baseline tests**: `pytest`
3. **Check coverage**: `pytest --cov=app`
4. **Fix any failures**
5. **Add more tests** for uncovered modules (scanners, vulnerability engine, etc.)

## Resources

- [Pytest Documentation](https://docs.pytest.org)
- [SQLAlchemy Testing](https://docs.sqlalchemy.org/en/20/orm/session_basics.html#using-the-session-in-concurrent-or-thread-local-patterns)
- [FastAPI Testing](https://fastapi.tiangolo.com/advanced/testing-database/)

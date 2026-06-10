#!/bin/bash
# ViperV2 Comprehensive System Test

set -e

echo "🚀 ViperV2 System Test - Complete Validation"
echo "=============================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
PASS=0
FAIL=0

# Helper functions
test_passed() {
    echo -e "${GREEN}✓ PASS:${NC} $1"
    ((PASS++))
}

test_failed() {
    echo -e "${RED}✗ FAIL:${NC} $1"
    ((FAIL++))
}

test_section() {
    echo ""
    echo -e "${YELLOW}📋 $1${NC}"
    echo "---"
}

# ======================
# Test 1: Backend Health
# ======================
test_section "Backend Health Checks"

if curl -s http://localhost:8001/health | grep -q "healthy"; then
    test_passed "Backend is running on port 8001"
else
    test_failed "Backend health check failed"
fi

if curl -s http://localhost:8001/ | grep -q "ViperV2"; then
    test_passed "Backend root endpoint responsive"
else
    test_failed "Backend root endpoint failed"
fi

# ======================
# Test 2: Database
# ======================
test_section "Database Connectivity"

if python3 -c "
from sqlalchemy import create_engine, text
engine = create_engine('sqlite:///./backend/viperv2.db')
with engine.connect() as conn:
    result = conn.execute(text('SELECT 1'))
    print(result.scalar())
" 2>/dev/null | grep -q "1"; then
    test_passed "Database connection successful"
else
    test_failed "Database connection failed"
fi

# ======================
# Test 3: API Endpoints
# ======================
test_section "API Endpoints"

# Test health endpoint
if curl -s http://localhost:8001/health -w "%{http_code}" | grep -q "200"; then
    test_passed "GET /health returns 200"
else
    test_failed "GET /health returned non-200"
fi

# Test docs endpoint
if curl -s http://localhost:8001/docs -w "%{http_code}" | grep -q "200"; then
    test_passed "GET /docs (Swagger UI) accessible"
else
    test_failed "GET /docs not accessible"
fi

# ======================
# Test 4: Frontend
# ======================
test_section "Frontend Availability"

if curl -s http://localhost:5173 | grep -q "VIPER"; then
    test_passed "Frontend accessible on port 5173"
else
    test_failed "Frontend not accessible"
fi

# ======================
# Test 5: Code Quality
# ======================
test_section "Code Quality Checks"

cd backend

# Check Python syntax
if python3 -m py_compile app/main.py 2>/dev/null; then
    test_passed "Backend Python syntax valid"
else
    test_failed "Backend has syntax errors"
fi

# Check imports
if python3 -c "import app.main" 2>/dev/null; then
    test_passed "Backend imports successful"
else
    test_failed "Backend import error"
fi

# Check database models
if python3 -c "from app.models.scan import ScanSession; from app.models.user import User" 2>/dev/null; then
    test_passed "Database models loadable"
else
    test_failed "Database models have errors"
fi

# Check authentication module
if python3 -c "from app.core.security import create_access_token, verify_token" 2>/dev/null; then
    test_passed "Security module functional"
else
    test_failed "Security module has errors"
fi

cd ..

# ======================
# Test 6: Requirements
# ======================
test_section "Dependency Installation"

if python3 -c "import pytest; import sqlalchemy; import fastapi; import pydantic" 2>/dev/null; then
    test_passed "Core dependencies installed"
else
    test_failed "Missing core dependencies"
fi

# ======================
# Test 7: File Structure
# ======================
test_section "Project Structure"

REQUIRED_DIRS=(
    "backend/app"
    "backend/app/api"
    "backend/app/models"
    "backend/tests"
    "backend/tests/api"
    "frontend/src"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        test_passed "Directory exists: $dir"
    else
        test_failed "Directory missing: $dir"
    fi
done

# ======================
# Test 8: Critical Files
# ======================
test_section "Critical Files"

REQUIRED_FILES=(
    "backend/app/main.py"
    "backend/app/core/config.py"
    "backend/app/core/security.py"
    "backend/app/models/user.py"
    "backend/requirements.txt"
    "frontend/src/App.jsx"
    "docker-compose.yml"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        test_passed "File exists: $file"
    else
        test_failed "File missing: $file"
    fi
done

# ======================
# Test 9: Git Status
# ======================
test_section "Git Repository"

if git rev-parse --git-dir > /dev/null 2>&1; then
    test_passed "Git repository initialized"

    COMMITS=$(git log --oneline | head -n 1 | cut -d' ' -f1)
    test_passed "Latest commit: $COMMITS"
else
    test_failed "Not a git repository"
fi

# ======================
# Summary
# ======================
echo ""
echo "=============================================="
echo -e "${GREEN}PASS: $PASS${NC} | ${RED}FAIL: $FAIL${NC}"
echo "=============================================="

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed!${NC}"
    exit 1
fi

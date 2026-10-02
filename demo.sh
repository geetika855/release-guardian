#!/usr/bin/env bash
# Demo: review the risky and safe fixtures via CLI, then exercise the API.
set -euo pipefail
cd "$(dirname "$0")"

PY=python3
if ! $PY -c "import fastapi" 2>/dev/null; then
  echo "creating .venv and installing dependencies..."
  $PY -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
  PY=.venv/bin/python
fi

echo "=== 1. CLI: risky manifest ==="
$PY -m src.cli review fixtures/risky | head -12

echo ""
echo "=== 2. CLI: safe manifest ==="
$PY -m src.cli review fixtures/safe | head -6

echo ""
echo "=== 3. API: /health and /review ==="
$PY - <<'EOF'
import json
from pathlib import Path
from fastapi.testclient import TestClient
from src.api import app

client = TestClient(app)
print("GET /health ->", client.get("/health").json())

risky = (Path("fixtures/risky/deployment.yaml")).read_text()
r = client.post("/review", json={"yaml": risky}).json()
print(f"POST /review (risky) -> score {r['score']}, verdict {r['verdict']}, "
      f"{r['counts']['critical']} critical / {r['counts']['high']} high")

safe = (Path("fixtures/safe/deployment.yaml")).read_text()
r = client.post("/review", json={"yaml": safe}).json()
print(f"POST /review (safe)  -> score {r['score']}, verdict {r['verdict']}")
EOF

echo ""
echo "=== 4. Tests ==="
$PY -m pytest -q 2>&1 | tail -1
echo "demo complete"

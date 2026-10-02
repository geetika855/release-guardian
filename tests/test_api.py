"""API tests: /health and /review against the fixture manifests."""

from pathlib import Path

from fastapi.testclient import TestClient

from src.api import app
from src.checks import ALL_CHECKS

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
client = TestClient(app)


def _fixture(name: str) -> str:
    return (FIXTURES / name / "deployment.yaml").read_text()


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["checks"] == len(ALL_CHECKS)


def test_review_risky_blocks():
    r = client.post("/review", json={"yaml": _fixture("risky")})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "BLOCK"
    assert body["counts"]["critical"] >= 2
    assert body["score"] < 40
    assert any(f["check_id"] == "SEC002" for f in body["findings"])


def test_review_safe_approves():
    r = client.post("/review", json={"yaml": _fixture("safe")})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "APPROVE"
    assert body["score"] >= 90


def test_review_rejects_bad_yaml():
    r = client.post("/review", json={"yaml": "key: [unclosed"})
    assert r.status_code == 422


def test_review_rejects_empty():
    r = client.post("/review", json={"yaml": "# just a comment\n"})
    assert r.status_code == 422

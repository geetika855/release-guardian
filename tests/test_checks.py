"""Tests for the release-guardian rule engine."""

from pathlib import Path

import pytest

from src.analyzer import analyze
from src.checks import (
    check_host_namespaces,
    check_image_tag,
    check_plaintext_secrets,
    check_resources,
    check_security_context,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _resource(podspec: dict, kind: str = "Deployment", name: str = "api"):
    return {"kind": kind, "metadata": {"name": name},
            "spec": {"template": {"spec": podspec}}}


def _container(**kw):
    base = {"name": "api", "image": "myapp:1.2.3"}
    base.update(kw)
    return base


def test_latest_image_flagged():
    r = _resource({"containers": [_container(image="myapp:latest")]})
    findings = list(check_image_tag(r, r["spec"]["template"]["spec"]))
    assert any(f.check_id == "IMG001" for f in findings)


def test_pinned_image_passes():
    r = _resource({"containers": [_container(image="myapp:1.2.3")]})
    findings = list(check_image_tag(r, r["spec"]["template"]["spec"]))
    assert not findings


def test_missing_limits_flagged():
    r = _resource({"containers": [_container()]})
    ids = {f.check_id for f in check_resources(r, r["spec"]["template"]["spec"])}
    assert {"RES001", "RES002"} <= ids


def test_privileged_is_critical():
    r = _resource({"containers": [_container(securityContext={"privileged": True})]})
    findings = list(check_security_context(r, r["spec"]["template"]["spec"]))
    crit = [f for f in findings if f.check_id == "SEC002"]
    assert crit and crit[0].severity == "critical"


def test_host_network_is_critical():
    r = _resource({"hostNetwork": True, "containers": [_container()]})
    findings = list(check_host_namespaces(r, r["spec"]["template"]["spec"]))
    assert any(f.severity == "critical" for f in findings)


def test_hardcoded_secret_flagged():
    c = _container(env=[{"name": "DB_PASSWORD", "value": "hunter2"}])
    r = _resource({"containers": [c]})
    findings = list(check_plaintext_secrets(r, r["spec"]["template"]["spec"]))
    assert any(f.check_id == "SEC006" for f in findings)


def test_secret_ref_passes():
    c = _container(env=[{"name": "DB_PASSWORD",
                         "valueFrom": {"secretKeyRef": {"name": "s", "key": "p"}}}])
    r = _resource({"containers": [c]})
    findings = list(check_plaintext_secrets(r, r["spec"]["template"]["spec"]))
    assert not findings


def test_risky_fixture_scores_low_and_blocks():
    report = analyze(FIXTURES / "risky")
    assert report.resources_scanned == 1
    assert report.counts["critical"] >= 2  # privileged + hostNetwork
    assert report.counts["high"] >= 4      # latest, limits, root, hostPath, secrets...
    assert report.verdict == "BLOCK"
    assert report.score < 40


def test_safe_fixture_scores_high_and_approves():
    report = analyze(FIXTURES / "safe")
    assert report.counts["critical"] == 0
    assert report.counts["high"] == 0
    assert report.verdict == "APPROVE"
    assert report.score >= 90


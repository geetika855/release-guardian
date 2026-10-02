# release-guardian

AI-assisted deployment risk reviewer: statically analyzes Kubernetes manifests
and produces a scored, actionable release report — so risky deploys get caught
*before* they hit the cluster.

## The problem

Most Kubernetes outages trace back to manifest misconfigurations: an image
retagged under `:latest`, a container with no memory limit, a Deployment with
no health probes, a secret committed as a plaintext env var. These are
checkable facts, not judgment calls — so they should be checked automatically,
on every change, before the rollout.

## What it does

Point it at a YAML file or directory of manifests. It runs a library of risk
checks and returns:

- **Risk score** 0–100, weighted by severity (critical 25, high 10, medium 5, low 2)
- **Verdict**: `BLOCK` (any critical finding), `REVIEW` (any high finding or score < 70), `APPROVE`
- **Findings**: each with the affected resource, a plain-English explanation, and a concrete fix

## Quickstart

```bash
pip install -r requirements.txt

# CLI: human-readable report, or --json for CI gates
python -m src.cli review fixtures/risky
python -m src.cli review path/to/manifests --json

# API
uvicorn src.api:app --port 8000
# GET  /health   -> {"status": "ok", "checks": 8, ...}
# POST /review   -> {"yaml": "<multi-doc YAML>"} returns the scored report

# Docker
docker compose up --build   # API on http://localhost:8000

# Full demo (CLI + API + tests)
./demo.sh
```

## Example

The deliberately bad fixture scores **0/100 → BLOCK** (privileged container,
hostNetwork, `:latest` image, hardcoded secrets…), while the hardened fixture
scores **100/100 → APPROVE**.

## Checks

| ID | Severity | What it flags |
|----|----------|---------------|
| IMG001 | high | Image uses `:latest` or no tag |
| RES001 / RES002 | high / medium | Missing resource limits / requests |
| PRB001 / PRB002 | medium | Missing liveness / readiness probes |
| SEC001 | high | Container may run as root |
| SEC002 | critical | Privileged container |
| SEC003 | medium | Privilege escalation not disabled |
| SEC004 | low | Writable root filesystem |
| SEC005 | high | Dangerous Linux capabilities (SYS_ADMIN, …) |
| SEC006 | high | Hardcoded secret in env var |
| HOST001–003 | critical | hostNetwork / hostPID / hostIPC |
| VOL001 | high | hostPath volume |
| HA001 | medium | Single-replica Deployment |

## Layout

```
src/
  checks.py     # rule library: pure functions, (resource, podspec) -> findings
  analyzer.py   # manifest loading, check orchestration, scoring, verdicts
  api.py        # FastAPI service: GET /health, POST /review
  cli.py        # `review` command: text and JSON reports
fixtures/
  risky/        # deliberately bad manifest  -> 0/100, BLOCK
  safe/         # hardened manifest          -> 100/100, APPROVE
tests/          # 14 tests: checks, fixtures, scoring, API
.github/workflows/ci.yml   # pytest -> docker build -> /health smoke test
```

## Why rules instead of an LLM?

Deterministic and explainable: the same manifest produces the same findings
every time, which is what lets it gate a CI pipeline. Manifests stay local —
nothing is sent to a third-party API. The AI layer belongs on top: LLM-written
release summaries grounded in these findings (roadmap).

## Honest notes

- Fixture corpus is small by design; the pipeline analyzes any manifest directory.
- The Docker image is built and smoke-tested in CI (no local Docker on the dev machine).
- No invented impact metrics: this flags risky patterns; it doesn't claim to have prevented any specific outage.

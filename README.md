# release-guardian

AI-assisted deployment risk reviewer: statically analyzes Kubernetes manifests
and produces a scored, actionable release report — so risky deploys get caught
*before* they hit the cluster.

## What it does

Point it at a YAML file or directory of Kubernetes manifests:

```bash
python -m src.cli review fixtures/risky
```

It runs a library of risk checks (images, resources, probes, security context,
host namespaces, secrets, HA) and outputs:

- **Risk score** 0–100 (weighted by severity: critical 25, high 10, medium 5, low 2)
- **Verdict**: `BLOCK` (any critical), `REVIEW` (any high or score < 70), `APPROVE`
- **Findings** with the affected resource, an explanation, and a concrete fix

```bash
python -m src.cli review <path> --json   # machine-readable, for CI gates
```

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
  checks.py     # the rule library (pure functions)
  analyzer.py   # manifest loading, check orchestration, scoring
  cli.py        # `review` command: text and JSON reports
fixtures/
  risky/        # deliberately bad manifest (scores 0/100, BLOCK)
  safe/         # hardened manifest (scores 100/100, APPROVE)
tests/          # 9 tests covering checks, fixtures, and scoring
```

## Run the tests

```bash
pip install -r requirements.txt
pytest
```

## Roadmap

- FastAPI service (`POST /review`) with scored reports
- Docker packaging + CI gate example
- LLM-written release summaries grounded in the findings (optional)

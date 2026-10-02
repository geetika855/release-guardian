"""FastAPI service: review Kubernetes manifests over HTTP.

Endpoints:
    GET  /health   service status + loaded check count
    POST /review   {"yaml": "<multi-doc YAML string>"} -> scored report
"""

from dataclasses import asdict

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .analyzer import analyze_resources
from .checks import ALL_CHECKS

app = FastAPI(title="release-guardian", version="0.2.0")


class ReviewRequest(BaseModel):
    yaml: str = Field(..., description="One or more Kubernetes manifests as a multi-doc YAML string.",
                      min_length=1)


@app.get("/health")
def health():
    return {"status": "ok", "checks": len(ALL_CHECKS), "version": app.version}


@app.post("/review")
def review(req: ReviewRequest):
    try:
        docs = [d for d in yaml.safe_load_all(req.yaml) if isinstance(d, dict)]
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid YAML: {exc}")
    if not docs:
        raise HTTPException(status_code=422, detail="No Kubernetes documents found in 'yaml'.")
    report = analyze_resources(docs)
    return {
        "resources_scanned": report.resources_scanned,
        "score": report.score,
        "verdict": report.verdict,
        "counts": report.counts,
        "findings": [asdict(f) for f in report.sorted_findings()],
    }

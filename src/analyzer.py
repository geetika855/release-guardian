"""Load Kubernetes manifests, run the check library, and score the release."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .checks import ALL_CHECKS, SEVERITY_ORDER, Finding

# Workload kinds and where their PodSpec lives.
_PODSPEC_PATHS = {
    "Deployment": ["spec", "template", "spec"],
    "StatefulSet": ["spec", "template", "spec"],
    "DaemonSet": ["spec", "template", "spec"],
    "ReplicaSet": ["spec", "template", "spec"],
    "ReplicationController": ["spec", "template", "spec"],
    "Job": ["spec", "template", "spec"],
    "CronJob": ["spec", "jobTemplate", "spec", "template", "spec"],
    "Pod": ["spec"],
}

# Points per finding, by severity. Score = 100 - total, floored at 0.
SEVERITY_POINTS = {"critical": 25, "high": 10, "medium": 5, "low": 2}


@dataclass
class Report:
    files_scanned: int
    resources_scanned: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return max(0, 100 - sum(SEVERITY_POINTS[f.severity] for f in self.findings))

    @property
    def counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def verdict(self) -> str:
        c = self.counts
        if c["critical"] > 0:
            return "BLOCK"
        if c["high"] > 0 or self.score < 70:
            return "REVIEW"
        return "APPROVE"

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])


def _podspec(resource: dict):
    path = _PODSPEC_PATHS.get(resource.get("kind", ""))
    if not path:
        return None
    node = resource
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node if isinstance(node, dict) else None


def load_resources(path: Path) -> tuple[list[dict], int]:
    """Load all YAML documents from a file or directory. Returns (resources, file_count)."""
    files = [path] if path.is_file() else sorted(path.rglob("*.yaml")) + sorted(path.rglob("*.yml"))
    resources, file_count = [], 0
    for f in files:
        if not f.is_file():
            continue
        file_count += 1
        with open(f) as fh:
            for doc in yaml.safe_load_all(fh):
                if isinstance(doc, dict) and doc.get("kind"):
                    resources.append(doc)
    return resources, file_count


def analyze_resources(resources: list[dict]) -> Report:
    """Run every check against an in-memory list of resource dicts."""
    findings: list[Finding] = []
    scanned = 0
    for resource in resources:
        podspec = _podspec(resource)
        if podspec is None:
            continue
        scanned += 1
        for check in ALL_CHECKS:
            findings.extend(check(resource, podspec))
    return Report(files_scanned=0, resources_scanned=scanned, findings=findings)


def analyze(path: Path) -> Report:
    """Run every check against every workload resource under path."""
    resources, file_count = load_resources(Path(path))
    report = analyze_resources(resources)
    report.files_scanned = file_count
    return report

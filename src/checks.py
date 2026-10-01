"""Static risk checks over Kubernetes manifests.

Each check inspects workload resources (Deployment, StatefulSet, DaemonSet,
Job, CronJob, Pod) and yields Findings for risky patterns. Checks are pure
functions: (resource, podspec, container) -> list[Finding].
"""

from dataclasses import dataclass, field


@dataclass
class Finding:
    check_id: str
    severity: str  # critical | high | medium | low
    title: str
    resource: str  # e.g. "Deployment/api"
    detail: str
    remediation: str


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "DAC_OVERRIDE",
    "SYS_RESOURCE",
    "MKNOD",
}


def _res_id(resource: dict) -> str:
    kind = resource.get("kind", "?")
    name = resource.get("metadata", {}).get("name", "?")
    return f"{kind}/{name}"


def _containers(podspec: dict):
    for c in podspec.get("containers", []):
        yield "container", c
    for c in podspec.get("initContainers", []):
        yield "initContainer", c


def check_image_tag(resource, podspec):
    """Flag untagged or :latest images (non-reproducible, surprising rollouts)."""
    for ctype, c in _containers(podspec):
        image = c.get("image", "")
        tag = image.rsplit(":", 1)[-1] if ":" in image else ""
        if not image or ":" not in image or tag == "latest":
            yield Finding(
                check_id="IMG001",
                severity="high",
                title="Image uses :latest or has no tag",
                resource=_res_id(resource),
                detail=f"{ctype} '{c.get('name')}' uses image '{image or '<none>'}'.",
                remediation="Pin an immutable tag or digest (e.g. myapp:1.4.2 or myapp@sha256:...).",
            )


def check_resources(resource, podspec):
    """Flag containers missing CPU/memory requests/limits."""
    for ctype, c in _containers(podspec):
        res = c.get("resources", {})
        limits, requests = res.get("limits", {}), res.get("requests", {})
        name = c.get("name")
        if not limits.get("cpu") or not limits.get("memory"):
            yield Finding(
                check_id="RES001",
                severity="high",
                title="Container missing resource limits",
                resource=_res_id(resource),
                detail=f"{ctype} '{name}' has no CPU/memory limits.",
                remediation="Set resources.limits for cpu and memory so one container can't starve the node.",
            )
        if not requests.get("cpu") or not requests.get("memory"):
            yield Finding(
                check_id="RES002",
                severity="medium",
                title="Container missing resource requests",
                resource=_res_id(resource),
                detail=f"{ctype} '{name}' has no CPU/memory requests.",
                remediation="Set resources.requests so the scheduler places pods correctly and HPA behaves.",
            )


def check_probes(resource, podspec):
    """Flag containers without liveness/readiness probes."""
    for ctype, c in _containers(podspec):
        name = c.get("name")
        if ctype == "initContainer":
            continue
        if not c.get("livenessProbe"):
            yield Finding(
                check_id="PRB001",
                severity="medium",
                title="Container missing liveness probe",
                resource=_res_id(resource),
                detail=f"Container '{name}' has no livenessProbe; deadlocks won't be restarted.",
                remediation="Add a livenessProbe (httpGet, tcpSocket, or exec).",
            )
        if not c.get("readinessProbe"):
            yield Finding(
                check_id="PRB002",
                severity="medium",
                title="Container missing readiness probe",
                resource=_res_id(resource),
                detail=f"Container '{name}' has no readinessProbe; it may receive traffic before it's ready.",
                remediation="Add a readinessProbe so rolling updates don't send traffic to unready pods.",
            )


def check_security_context(resource, podspec):
    """Flag pods/containers that can run as root or escalate privileges."""
    pod_sc = podspec.get("securityContext", {})
    for ctype, c in _containers(podspec):
        sc = c.get("securityContext", {})
        name = c.get("name")
        run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        if run_as_non_root is not True:
            yield Finding(
                check_id="SEC001",
                severity="high",
                title="Container may run as root",
                resource=_res_id(resource),
                detail=f"{ctype} '{name}' does not set runAsNonRoot: true.",
                remediation="Set securityContext.runAsNonRoot: true (and a runAsUser > 0).",
            )
        if sc.get("privileged") is True:
            yield Finding(
                check_id="SEC002",
                severity="critical",
                title="Privileged container",
                resource=_res_id(resource),
                detail=f"{ctype} '{name}' runs privileged: full host access.",
                remediation="Remove privileged: true; grant only the specific capabilities needed.",
            )
        if sc.get("allowPrivilegeEscalation", True) is not False:
            yield Finding(
                check_id="SEC003",
                severity="medium",
                title="Privilege escalation not disabled",
                resource=_res_id(resource),
                detail=f"{ctype} '{name}' does not set allowPrivilegeEscalation: false.",
                remediation="Set securityContext.allowPrivilegeEscalation: false.",
            )
        if sc.get("readOnlyRootFilesystem") is not True and ctype == "container":
            yield Finding(
                check_id="SEC004",
                severity="low",
                title="Root filesystem is writable",
                resource=_res_id(resource),
                detail=f"Container '{name}' does not set readOnlyRootFilesystem: true.",
                remediation="Set securityContext.readOnlyRootFilesystem: true; mount writable volumes where needed.",
            )
        caps = (sc.get("capabilities", {}) or {}).get("add", []) or []
        dangerous = sorted(set(caps) & DANGEROUS_CAPABILITIES)
        if dangerous:
            yield Finding(
                check_id="SEC005",
                severity="high",
                title="Dangerous Linux capabilities added",
                resource=_res_id(resource),
                detail=f"{ctype} '{name}' adds capabilities: {', '.join(dangerous)}.",
                remediation="Drop to the minimal capability set; avoid SYS_ADMIN/NET_ADMIN unless justified.",
            )


def check_host_namespaces(resource, podspec):
    """Flag hostNetwork/hostPID/hostIPC (breaks pod isolation)."""
    for field_name, check_id in (
        ("hostNetwork", "HOST001"),
        ("hostPID", "HOST002"),
        ("hostIPC", "HOST003"),
    ):
        if podspec.get(field_name) is True:
            yield Finding(
                check_id=check_id,
                severity="critical",
                title=f"Pod uses host {field_name[4:].lower()} namespace",
                resource=_res_id(resource),
                detail=f"podspec sets {field_name}: true.",
                remediation=f"Remove {field_name}: true; use regular pod networking unless this is a CNI/CSI-class daemon.",
            )


def check_hostpath_volumes(resource, podspec):
    """Flag hostPath volumes (host filesystem exposure)."""
    for v in podspec.get("volumes", []):
        if "hostPath" in v:
            yield Finding(
                check_id="VOL001",
                severity="high",
                title="hostPath volume mounted",
                resource=_res_id(resource),
                detail=f"Volume '{v.get('name')}' mounts hostPath '{v['hostPath'].get('path')}'.",
                remediation="Use a PersistentVolumeClaim or emptyDir instead of hostPath.",
            )


def check_plaintext_secrets(resource, podspec):
    """Flag env vars with hardcoded secret values instead of secretKeyRef."""
    for ctype, c in _containers(podspec):
        for e in c.get("env", []):
            if "value" in e and any(
                hint in e.get("name", "").upper()
                for hint in ("PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL")
            ):
                yield Finding(
                    check_id="SEC006",
                    severity="high",
                    title="Possible hardcoded secret in env var",
                    resource=_res_id(resource),
                    detail=f"{ctype} '{c.get('name')}' sets env '{e['name']}' as a plaintext value.",
                    remediation="Use valueFrom.secretKeyRef to inject secrets; never commit plaintext credentials.",
                )


def check_replicas(resource, podspec):
    """Flag single-replica Deployments (no HA) and missing PDBs."""
    if resource.get("kind") != "Deployment":
        return
    spec = resource.get("spec", {})
    replicas = spec.get("replicas", 1)
    if replicas is not None and replicas < 2:
        yield Finding(
            check_id="HA001",
            severity="medium",
            title="Single replica: no high availability",
            resource=_res_id(resource),
            detail=f"Deployment runs {replicas} replica(s); any node failure or rollout error causes downtime.",
            remediation="Run at least 2 replicas (3+ for production) across zones.",
        )


ALL_CHECKS = [
    check_image_tag,
    check_resources,
    check_probes,
    check_security_context,
    check_host_namespaces,
    check_hostpath_volumes,
    check_plaintext_secrets,
    check_replicas,
]

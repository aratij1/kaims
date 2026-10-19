from __future__ import annotations

import argparse
from pathlib import Path

REQUIRED_DOCS = (
    "PHASE_9_GAP_ANALYSIS.md",
    "PHASE_9_ARCHITECTURE.md",
    "PHASE_9_CONNECTOR_MODEL.md",
    "PHASE_9_OPERATIONAL_DIGITAL_TWIN.md",
    "PHASE_9_REMEDIATION_SAFETY.md",
    "PHASE_9_TEST_PLAN.md",
    "PHASE_9_MIGRATION_GUIDE.md",
    "PHASE_9_IMPLEMENTATION_SUMMARY.md",
)
REQUIRED_METRICS = (
    "kaiops_request_latency_seconds",
    "kaiops_agent_stage_latency_seconds",
    "kaiops_llm_latency_seconds",
    "kaiops_llm_tokens_total",
    "kaiops_llm_cost_usd_total",
    "kaiops_connector_latency_seconds",
    "kaiops_queue_depth",
    "kaiops_rca_confidence",
    "kaiops_approval_decisions_total",
    "kaiops_automation_decisions_total",
    "kaiops_remediation_outcomes_total",
    "kaiops_rollback_outcomes_total",
    "kaiops_validation_outcomes_total",
    "kaiops_incident_mttr_seconds",
    "kaiops_noise_reduction_ratio",
    "kaiops_false_automation_total",
)


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    for name in REQUIRED_DOCS:
        path = root / "docs" / name
        if not path.is_file() or path.stat().st_size < 100:
            failures.append(f"missing or empty deliverable: docs/{name}")
    required_files = (
        "docs/metadata/canonical-event-envelope-v1.schema.json",
        "observability/otel-collector.yml",
        "backend/src/common/common/capability_registry.py",
        "backend/src/common/common/operational_models.py",
        "backend/src/connector-hub/app.py",
        "frontend/react/src/features/incidents/IncidentCommand.tsx",
    )
    for relative in required_files:
        if not (root / relative).is_file():
            failures.append(f"missing production artifact: {relative}")
    telemetry_path = root / "backend/src/common/common/telemetry.py"
    telemetry = telemetry_path.read_text(encoding="utf-8") if telemetry_path.is_file() else ""
    for metric in REQUIRED_METRICS:
        if metric not in telemetry:
            failures.append(f"missing metric contract: {metric}")
    compose_path = root / "docker-compose.yml"
    if not compose_path.is_file():
        failures.append("missing production artifact: docker-compose.yml")
    else:
        compose = compose_path.read_text(encoding="utf-8")
        for service in ("otel-collector:", "connector-hub:", "cloud-operations:", "remediation-engine:"):
            if service not in compose:
                failures.append(f"missing compose service: {service[:-1]}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate KaiMS Phase 9 production-readiness artifacts")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    failures = validate(parser.parse_args().root.resolve())
    if failures:
        print("Phase 9 production readiness: BLOCKED")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("Phase 9 production readiness: artifact gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

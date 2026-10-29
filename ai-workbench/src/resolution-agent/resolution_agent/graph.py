from __future__ import annotations

from common.evidence_source_policy import is_alert_artifact

from common.investigation_gaps import blocking_investigation_gaps

import asyncio
import hashlib
import json
import logging
import os
import re
from time import monotonic
from enum import StrEnum
from typing import Any, TypedDict
from uuid import NAMESPACE_URL, uuid5

import httpx
from ai_workbench_common.agent_runtime import AgentRuntime, ContextFailure, ValidationError
from ai_workbench_common.agentic import AgentContext, BaseAgent
from ai_workbench_common.memory_store import InMemoryStore, MemoryStore
from ai_workbench_common.model_evaluation import AzureAIEvaluationClient, EvaluationResult, build_quality_evaluation
from ai_workbench_common.model_gateway import GenerationRequest, HttpModelGateway, ModelGateway, RouterModelGateway
from ai_workbench_common.models import Context, Evidence
from ai_workbench_common.prompts import (
    PROMPT_ASSESS_IMPACT,
    PROMPT_IDENTIFY_ROOT_CAUSE,
    PROMPT_RECOMMEND_REMEDIATION,
)
from ai_workbench_common.resolution_quality import assess_evidence_quality, remediation_quality_gate
from common.config import get_settings
from common.models import AlertSeverity, Recommendation
from common.telemetry import AGENT_STAGE_LATENCY
from langgraph.graph import END, StateGraph

logger = logging.getLogger("kaiops.resolution_agent")


def _canonicalize_rationale_confidence(rationale: str, confidence: float) -> str:
    """Replace an intermediate RCA score with the final bounded diagnostic score."""

    text = str(rationale or "").strip()
    canonical = f"canonical diagnostic confidence={confidence:.2f}"
    if re.search(r"(?:canonical diagnostic )?confidence=\d+(?:\.\d+)?", text):
        return re.sub(
            r"(?:canonical diagnostic )?confidence=\d+(?:\.\d+)?",
            canonical,
            text,
            count=1,
        )
    return f"{text} {canonical}.".strip()


class ModelTask(StrEnum):
    """Mirrors model_router.ModelTask's wire values without importing that service's package."""

    RCA = "rca"
    IMPACT = "impact"
    FIX = "fix"
    SUMMARIZATION = "summarization"
    GENERAL = "general"


class ResolutionState(TypedDict, total=False):
    context: Context
    gathered_context: dict[str, Any]
    root_cause: str
    rca_grounding: dict[str, Any]
    impact: str
    recommended_action: str
    remediation_target: str
    confidence: float
    rationale: str
    commands: list[str]
    model_usage: list[dict[str, Any]]
    model_calls: list[dict[str, Any]]
    rca_analysis: dict[str, Any]
    impact_analysis: dict[str, Any]
    remediation_analysis: dict[str, Any]
    investigation_report: dict[str, Any]
    hypothesis_analysis: dict[str, Any]


class ResolutionIntelligenceAgent(BaseAgent):
    name = "resolution-agent"

    def __init__(
        self,
        model_router: Any | None = None,
        model_gateway: ModelGateway | None = None,
        runtime: AgentRuntime | None = None,
        memory_store: MemoryStore | None = None,
        evaluation_client: AzureAIEvaluationClient | None = None,
    ) -> None:
        settings = get_settings()
        self.model_router = model_router
        if model_gateway is not None:
            self.model_gateway = model_gateway
        elif model_router is not None:
            # Allows tests/tools to inject an in-process ModelRouter-like object directly.
            self.model_gateway = RouterModelGateway(model_router)
        else:
            self.model_gateway = HttpModelGateway(
                settings.model_router_url,
                timeout_seconds=settings.llm_request_timeout_seconds,
                max_payload_bytes=settings.resolution_model_payload_max_bytes,
            )
        self.runtime = runtime or AgentRuntime(max_attempts=2)
        self.memory_store = memory_store or InMemoryStore()
        self.evaluation_client = evaluation_client or AzureAIEvaluationClient(settings)
        self.evaluation_service_url = settings.evaluation_service_url
        # Bound each model call so a single blocked provider cannot stall event consumption.
        # Mirrors settings.llm_request_timeout_seconds so operators can raise/lower both the
        # gateway's own timeout and this step-level guard from one place.
        self.model_step_timeout_seconds = settings.llm_request_timeout_seconds
        # RCA is the only model step required on the synchronous alert path.
        # Impact and remediation already have evidence-aware deterministic
        # builders below; making two additional remote calls serialized every
        # alert added 30-90 seconds without being required to persist an RCA.
        self.deep_analysis_enabled = str(
            os.getenv("RESOLUTION_DEEP_ANALYSIS_ENABLED", "false")
        ).strip().lower() in {"1", "true", "yes", "on"}
        # Separate impact assessment from optional remediation-plan generation.
        # Preserve the existing model-call policy unless explicitly configured.
        self.impact_analysis_enabled = str(
            os.getenv("RESOLUTION_IMPACT_ANALYSIS_ENABLED", str(self.deep_analysis_enabled))
        ).strip().lower() in {"1", "true", "yes", "on"}
        # Keeps strong references to fire-and-forget evaluation-publish tasks so they
        # aren't garbage-collected mid-flight; discarded automatically once done.
        self._background_tasks: set[asyncio.Task[None]] = set()
        self.graph = self._build_graph()

    @staticmethod
    def _norm(value: Any) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _model_call_audit(
        *,
        task: ModelTask,
        response: dict[str, Any],
        prompt: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Return traceable model-call metadata without operational content."""

        prompt_bytes = prompt.encode("utf-8")
        payload_bytes = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        response_bytes = str(response.get("content") or "").encode("utf-8")
        usage = dict(response.get("usage") or {})
        return {
            "task": task.value,
            "provider": str(response.get("model") or usage.get("provider") or "unknown"),
            "model": str(usage.get("model") or "unknown"),
            "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
            "prompt_bytes": len(prompt_bytes),
            "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
            "payload_bytes": len(payload_bytes),
            "response_sha256": hashlib.sha256(response_bytes).hexdigest(),
            "response_bytes": len(response_bytes),
            "usage": usage,
        }

    @staticmethod
    def _extract_runbook_commands(runbook: str, *, max_items: int = 4) -> list[str]:
        if not str(runbook or "").strip():
            return []
        commands: list[str] = []
        seen: set[str] = set()
        # context-agent's write_rag_document emits one fenced ```bash block per remediation
        # step under a single "## Remediation Script" heading (see context-agent/app.py,
        # _execution_script_lines/write_rag_document). Scope to that section, then pull every
        # fence inside it -- a single non-greedy regex spanning to the first ``` would only
        # ever see the first step and silently drop the rest of a multi-command runbook.
        section_match = re.search(
            r"##\s*Remediation Script\s*([\s\S]*?)(?=\n##\s|\Z)",
            str(runbook),
            flags=re.IGNORECASE,
        )
        if section_match:
            fences = re.findall(
                r"```(?:bash|sh|shell)?\s*([\s\S]*?)```",
                section_match.group(1),
                flags=re.IGNORECASE,
            )
            for fence in fences:
                script = "; ".join(
                    line.strip()
                    for line in fence.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ).strip()
                if script and script.lower() not in seen:
                    commands.append(script)
                    seen.add(script.lower())
                if len(commands) >= max_items:
                    return commands
            if commands:
                return commands
        for line in str(runbook).splitlines():
            token = line.strip().lstrip("- ").strip().strip("`")
            if not token:
                continue
            token = re.sub(r"^\s*(cmd|command|script|query)\s*:\s*", "", token, flags=re.IGNORECASE).strip()
            if token.startswith("#"):
                continue
            # Capture command-like steps while avoiding prose-heavy runbook lines.
            if (
                token.startswith(("bash ", "sh ", "pwsh ", "powershell ", "python ", "curl ", "docker ", "systemctl "))
                or token.startswith(("kubectl ", "helm ", "terraform ", "ansible-playbook ", "redis-cli ", "mysql "))
                or token.startswith("scripts/")
                or token.startswith("./")
                or token.startswith("Invoke-")
                or token.startswith("Get-")
            ):
                if token.lower() in seen:
                    continue
                commands.append(token)
                seen.add(token.lower())
            if len(commands) >= max_items:
                break
        return commands

    @staticmethod
    def _sanitize_commands(commands: list[str], *, max_items: int = 4) -> list[str]:
        sanitized: list[str] = []
        seen: set[str] = set()
        for raw in commands:
            token = str(raw or "").strip().strip("`")
            if not token:
                continue
            token = re.sub(r"^\s*(cmd|command|script|query)\s*:\s*", "", token, flags=re.IGNORECASE).strip()
            if not token or token.startswith("#"):
                continue
            if token.lower().startswith("preview only"):
                continue
            if token.lower().startswith("recommended_action"):
                continue
            key = token.lower()
            if key in seen:
                continue
            seen.add(key)
            sanitized.append(token)
            if len(sanitized) >= max_items:
                break
        return sanitized

    @staticmethod
    def _model_call_is_fallback(usage: dict[str, Any] | None) -> bool:
        if not isinstance(usage, dict):
            return False
        provider = ResolutionIntelligenceAgent._norm(usage.get("provider"))
        model = ResolutionIntelligenceAgent._norm(usage.get("model"))
        return (
            bool(usage.get("fallback"))
            or "fallback" in provider
            or "fallback" in model
            or "error" in usage
        )

    @staticmethod
    def _looks_like_instruction_template(value: str) -> bool:
        text = str(value or "").strip().lower()
        if not text:
            return False
        markers = [
            "scenario:",
            "immediate triage:",
            "remediation:",
            "verification:",
            "identify the most likely root cause using only supplied incident",
            "assess customer, service, dependency, and business impact",
            "apply a low-risk mitigation",
            "confirm recovery in dashboards and logs",
        ]
        return sum(1 for marker in markers if marker in text) >= 2

    @staticmethod
    def _extract_model_object(content: Any) -> dict[str, Any] | None:
        text = str(content or "").strip()
        if not text:
            return None
        fenced = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE)
        candidates = [fenced.group(1).strip()] if fenced else []
        candidates.append(text)
        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace >= 0 and last_brace > first_brace:
            candidates.append(text[first_brace:last_brace + 1])
        for candidate in candidates:
            try:
                parsed = json.loads(candidate)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, dict):
                return parsed
        return None

    @staticmethod
    def _extract_model_text(content: Any, *, keys: tuple[str, ...], fallback_text: str) -> str:
        text = str(content or "").strip()
        if not text:
            return fallback_text
        if ResolutionIntelligenceAgent._looks_like_instruction_template(text):
            return fallback_text
        parsed = ResolutionIntelligenceAgent._extract_model_object(text)
        if parsed is None:
            # A model can return JSON-looking but syntactically invalid output
            # (for example, set-like braces around multiple impact strings).
            # Do not persist that machine payload as user-facing prose.
            if text.startswith(("{", "[", "```")) or text.endswith(("}", "]", "```")):
                return fallback_text
            return text
        metadata = parsed.get("metadata") if isinstance(parsed.get("metadata"), dict) else {}
        if metadata.get("fallback"):
            return fallback_text
        for key in keys:
            value = parsed.get(key)
            candidate = str(value or "").strip()
            if candidate and not ResolutionIntelligenceAgent._looks_like_instruction_template(candidate):
                return candidate
        return fallback_text

    @staticmethod
    def _validated_evidence_ids(values: Any, valid_ids: set[str]) -> list[str]:
        if not isinstance(values, list):
            return []
        accepted: list[str] = []
        for value in values:
            raw = str(value or "").strip()
            match = raw if raw in valid_ids else next(
                (
                    evidence_id
                    for evidence_id in valid_ids
                    if raw.startswith(evidence_id)
                    and raw[len(evidence_id):len(evidence_id) + 1] in {"", ":", " ", "-", "—"}
                ),
                "",
            )
            if match and match not in accepted:
                accepted.append(match)
        return accepted

    @staticmethod
    def _is_insufficient_analysis_text(value: str, *, service: str) -> bool:
        text = ResolutionIntelligenceAgent._norm(value)
        if not text:
            return True
        generic_markers = [
            "evidence is insufficient",
            "unable to determine root cause",
            "insufficient information",
            "model synthesis was unavailable",
            "model synthesis unavailable",
            "likely service degradation",
            "requires immediate triage",
        ]
        if any(marker in text for marker in generic_markers):
            return True
        service_token = ResolutionIntelligenceAgent._norm(service)
        if service_token and text in {
            service_token,
            f"{service_token} latency",
            f"likely degradation in {service_token}",
        }:
            return True
        return False

    @staticmethod
    def _discovery_report_analysis(context: Context) -> dict[str, Any]:
        discovery_report = (
            context.metadata.get("discovery_report")
            if isinstance(context.metadata.get("discovery_report"), dict)
            else {}
        )
        analysis = discovery_report.get("report") if isinstance(discovery_report.get("report"), dict) else {}
        return analysis

    def _build_external_rca_fallback(
        self,
        *,
        context: Context,
        gathered_context: dict[str, Any],
        current_text: str,
    ) -> tuple[str, dict[str, Any]]:
        analysis = self._discovery_report_analysis(context)
        hypotheses = analysis.get("hypotheses") if isinstance(analysis.get("hypotheses"), list) else []
        primary = hypotheses[0] if hypotheses and isinstance(hypotheses[0], dict) else {}
        cause = str(primary.get("claim") or primary.get("cause") or primary.get("summary") or analysis.get("summary") or "").strip()
        confidence_raw = primary.get("confidence")
        try:
            confidence = max(0.0, min(0.6, float(confidence_raw)))
        except (TypeError, ValueError):
            confidence = 0.45

        code_review = gathered_context.get("code_review") if isinstance(gathered_context.get("code_review"), dict) else {}
        code_findings = code_review.get("findings") if isinstance(code_review.get("findings"), list) else []
        grounded_code_finding = next((item for item in code_findings if isinstance(item, dict)), {})
        detected_errors = gathered_context.get("detected_errors") if isinstance(gathered_context.get("detected_errors"), list) else []
        first_error = detected_errors[0] if detected_errors and isinstance(detected_errors[0], dict) else {}
        first_signal = str(first_error.get("message") or "").strip()
        if not first_signal:
            log_rows = gathered_context.get("log_intelligence") if isinstance(gathered_context.get("log_intelligence"), list) else []
            if log_rows and isinstance(log_rows[0], dict):
                first_signal = str(log_rows[0].get("snippet") or "").strip()
        first_signal = first_signal[:240]

        finding_title = str(grounded_code_finding.get("title") or "").strip()
        finding_explanation = str(grounded_code_finding.get("explanation") or "").strip()
        finding_source = str(grounded_code_finding.get("source_uri") or "").strip()
        if finding_title:
            finding_detail = finding_explanation or finding_title
            source_suffix = f" in {finding_source}" if finding_source else ""
            cause = (
                f"Code review identified '{finding_title}'{source_suffix}: {finding_detail}. "
                "This is an evidence-grounded candidate contributor, not a confirmed root cause"
            )
        if not cause:
            cause = str(current_text or "").strip()
        if self._is_insufficient_analysis_text(cause, service=str(context.alert.service or "")):
            alert_name = str(context.alert.name or "unnamed alert").strip()
            alert_description = str(context.alert.description or "").strip()[:300]
            observed = f" The alert reports: {alert_description}." if alert_description else ""
            cause = (
                f"No unique root cause has been validated for {context.alert.service}/{alert_name}."
                f"{observed} Additional correlated evidence is required"
            )

        cause = cause.rstrip(" .")
        first_signal = first_signal.rstrip(" .")
        signal_fragment = f" Observed local signal: {first_signal}." if first_signal else ""
        synthesized = (
            f"Alert-specific RCA hypothesis: {cause}. "
            "Treat this as provisional until telemetry, logs, and the cited source-code evidence agree."
            f"{signal_fragment}"
        ).strip()

        citations = analysis.get("citations") if isinstance(analysis.get("citations"), list) else []
        metadata = {
            "used": bool(
                grounded_code_finding
                or analysis.get("external_knowledge_used")
                or analysis.get("external_knowledge_eligible")
                or hypotheses
            ),
            "eligible": bool(analysis.get("external_knowledge_eligible")),
            "tools": list(analysis.get("external_tools_used", [])) if isinstance(analysis.get("external_tools_used"), list) else [],
            "citations": [str(item) for item in citations if str(item or "").strip()][:8],
            "confidence": confidence,
            "code_review_finding_used": bool(grounded_code_finding),
        }
        return synthesized, metadata

    def _build_external_impact_fallback(
        self,
        *,
        context: Context,
        gathered_context: dict[str, Any],
        current_text: str,
    ) -> tuple[str, dict[str, Any]]:
        analysis = self._discovery_report_analysis(context)
        affected_components = (
            analysis.get("affected_components") if isinstance(analysis.get("affected_components"), list) else []
        )
        affected_preview = ", ".join(str(item) for item in affected_components[:4] if str(item or "").strip())
        dependency_services = gathered_context.get("dependency_services") if isinstance(gathered_context.get("dependency_services"), list) else []
        dependency_preview = ", ".join(str(item) for item in dependency_services[:3] if str(item or "").strip())
        impact_basis = str(analysis.get("summary") or current_text or "").strip()
        if self._is_insufficient_analysis_text(impact_basis, service=str(context.alert.service or "")):
            impact_basis = (
                f"{context.alert.service.title()} may impact user-facing reliability, alerting quality, and downstream dependencies "
                "until remediation is validated"
            )

        scope_bits = []
        if affected_preview:
            scope_bits.append(f"affected components: {affected_preview}")
        if dependency_preview:
            scope_bits.append(f"dependency watchlist: {dependency_preview}")
        scope_text = f" ({'; '.join(scope_bits)})" if scope_bits else ""
        synthesized = f"Knowledge-assisted impact assessment: {impact_basis}.{scope_text}".strip()

        citations = analysis.get("citations") if isinstance(analysis.get("citations"), list) else []
        metadata = {
            "used": bool(analysis.get("external_knowledge_used") or analysis.get("external_knowledge_eligible") or affected_components),
            "eligible": bool(analysis.get("external_knowledge_eligible")),
            "tools": list(analysis.get("external_tools_used", [])) if isinstance(analysis.get("external_tools_used"), list) else [],
            "citations": [str(item) for item in citations if str(item or "").strip()][:8],
        }
        return synthesized, metadata

    @staticmethod
    def _extract_runbook_section(runbook: str, heading_pattern: str) -> str:
        if not str(runbook or "").strip():
            return ""
        match = re.search(
            rf"##\s*(?:{heading_pattern})\s*\n+([\s\S]*?)(?=\n##\s|\n###\s|\Z)",
            str(runbook),
            flags=re.IGNORECASE,
        )
        if not match:
            return ""
        lines = [
            line.strip()
            for line in match.group(1).splitlines()
            if line.strip() and not line.strip().startswith("```")
        ]
        return " ".join(lines).strip()

    def _infer_root_cause(self, context: Context, model_root_cause: str) -> str:
        human_guided = (context.metadata or {}).get("human_guided_input") if isinstance(context.metadata, dict) else {}
        if isinstance(human_guided, dict):
            human_rca = str(human_guided.get("root_cause") or human_guided.get("observed_symptoms") or "").strip()
            if human_rca:
                return human_rca
        raw_description = str(context.alert.description or "").strip()
        normalized_description = self._norm(raw_description)
        if (
            ("error 1227" in normalized_description or "access denied" in normalized_description)
            and "replication client" in normalized_description
            and ("slave_status" in normalized_description or "replica" in normalized_description)
        ):
            return (
                "The MySQL account used by mysql-exporter lacks the REPLICATION CLIENT privilege required by "
                "the slave_status collector, so MySQL rejects that scrape with error 1227."
            )
        # A retrieved deployment/change is context, not proof of causality. Only
        # promote a deployment when the alert itself explicitly identifies it.
        deployment = str(
            context.alert.labels.get("deployment")
            or context.alert.labels.get("release")
            or context.alert.labels.get("version")
            or ""
        ).strip()
        if deployment and any(
            keyword in normalized_description for keyword in ["deploy", "release", "rollout", "version"]
        ):
            return f"The alert reports degradation after deployment {deployment}; confirm the rollout diff and timing before treating it as causal."
        if str(context.runbook or "").strip() and self._is_insufficient_analysis_text(
            model_root_cause, service=str(context.alert.service or "")
        ):
            runbook_rca = self._extract_runbook_section(
                str(context.runbook),
                r"(?:Observed\s+)?Symptoms\s*&\s*Root Cause|Root Cause",
            )
            if runbook_rca:
                iterative = (
                    (context.metadata or {}).get("iterative_investigation")
                    if isinstance(context.metadata, dict)
                    else {}
                )
                if isinstance(iterative, dict) and iterative.get("conclusive") is True:
                    return runbook_rca
                return f"Hypothesis (Runbook Guidance - Unconfirmed): {runbook_rca}"

        return str(model_root_cause or f"Likely degradation in {context.alert.service}").strip()

    def _infer_action_and_commands(
        self, context: Context, root_cause: str, model_action: str
    ) -> tuple[str, list[str], str, list[str], str]:
        """Returns (action, commands, remediation_target, validation_queries, rollback_plan).

        validation_queries/rollback_plan are deterministic defaults for the fast path
        (RESOLUTION_DEEP_ANALYSIS_ENABLED=false) where no model ever supplies them.
        `commands` is unchanged from before this field was added -- remediation-engine
        reads recommendation.commands directly to execute, so its contents must not
        shift based on this addition."""
        description = self._norm(context.alert.description)
        root = self._norm(root_cause)
        labels = context.alert.labels if isinstance(context.alert.labels, dict) else {}
        external_target = str(labels.get("instance") or labels.get("target") or "").strip()
        if not external_target:
            match = re.search(r"https?://[^\s]+", str(context.alert.description or ""))
            external_target = match.group(0).rstrip(".,)") if match else ""
        is_public_http_target = external_target.lower().startswith(("http://", "https://")) and not any(
            token in external_target.lower() for token in ("localhost", "127.0.0.1", ".cluster.local", ".svc", "host.docker.internal")
        )
        is_external_probe = bool(external_target) and (
            is_public_http_target
            or
            str(labels.get("external") or "").lower() == "true"
            or "public-internet" in self._norm(context.alert.environment)
            or "probe" in description
        )
        if is_external_probe:
            safe_target = external_target.replace('"', "")
            return (
                "Verify the external endpoint from the monitoring probe and escalate to the provider if the outage is confirmed.",
                [f'curl --fail --silent --show-error --location --max-time 15 "{safe_target}"'],
                str(context.alert.service or safe_target).strip(),
                [f'curl --fail --silent --show-error --location --max-time 15 "{safe_target}"'],
                "No rollback is required for this read-only diagnostic; it does not change the external service or KaiMS configuration.",
            )
        if "replication client privilege" in root and "mysql-exporter" in root:
            return (
                "Verify the exporter account and grant only REPLICATION CLIENT through the approved database-access process, then validate slave_status metrics.",
                [
                    "mysql -e \"SELECT CURRENT_USER(); SHOW GRANTS FOR CURRENT_USER();\"",
                    "mysql -e \"SHOW REPLICA STATUS\\G\"",
                ],
                str(context.alert.service or "mysql-exporter").strip(),
                ["mysql -e \"SHOW REPLICA STATUS\\G\" -- confirm replication resumes after the grant"],
                "No rollback needed: granting REPLICATION CLIENT is read-only and does not modify data. "
                "If the privilege should not be permanent, revoke it: REVOKE REPLICATION CLIENT ON *.* FROM CURRENT_USER();",
            )
        mysql_signal = " ".join((description, root, self._norm(context.alert.name), self._norm(context.alert.service)))
        if "mysql" in mysql_signal and any(token in mysql_signal for token in ("table", "row count", "growth", "capacity", "disk")):
            table = re.sub(r"[^a-zA-Z0-9_]", "", str(labels.get("table") or "alerts")) or "alerts"
            return (
                "Collect MySQL capacity, growth, workload, and lock evidence; select a reviewed retention or capacity action only after the breach mechanism is proven.",
                [
                    f'mysql -e "SELECT COUNT(*) AS row_count, MIN(created_at) AS oldest_row, MAX(created_at) AS newest_row FROM {table};"',
                    f'mysql -e "SELECT table_rows, ROUND((data_length + index_length)/1024/1024,2) AS total_mb FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=\'{table}\';"',
                    'mysql -e "SELECT variable_name, variable_value FROM performance_schema.global_status WHERE variable_name IN (\'Threads_connected\',\'Threads_running\',\'Slow_queries\',\'Aborted_connects\');"',
                    'mysql -e "SELECT COUNT(*) AS lock_waits FROM performance_schema.data_lock_waits;"',
                ],
                str(context.alert.service or "mysql").strip(),
                [f'mysql -e "SELECT COUNT(*) AS row_count, MIN(created_at) AS oldest_row, MAX(created_at) AS newest_row FROM {table};"'],
                "No rollback is required for this read-only diagnostic plan. Any later archive, purge, index, or capacity change must define its own backup, rollback, and validation contract.",
            )
        runbook = str(context.runbook or "")
        human_guided = (context.metadata or {}).get("human_guided_input") if isinstance(context.metadata, dict) else {}
        if isinstance(human_guided, dict) and str(human_guided.get("remediation_steps") or "").strip():
            target = str(context.alert.service or "service").strip()
            guided_steps = str(human_guided["remediation_steps"]).strip()
            extracted_cmds = self._sanitize_commands(self._extract_runbook_commands(guided_steps or runbook), max_items=4)
            return (
                guided_steps,
                extracted_cmds or ["echo 'Execute human-guided remediation steps'"],
                target,
                ["Re-check the alert or dashboard that triggered this incident for recovery"],
                "Follow the runbook's own rollback guidance if remediation does not resolve the incident; "
                "no automated rollback is defined for custom runbook steps.",
            )
        runbook_text = self._norm(runbook)
        runbook_matches_alert = any(
            token and token in runbook_text
            for token in [self._norm(context.alert.service), self._norm(context.alert.name)]
        )
        runbook_commands = self._sanitize_commands(self._extract_runbook_commands(runbook), max_items=4) if runbook_matches_alert else []
        if runbook_commands:
            target = str(context.alert.service or "service").strip()
            return (
                "Execute approved runbook remediation script and validation checks",
                runbook_commands,
                target,
                ["Re-check the alert or dashboard that triggered this incident for recovery"],
                "Follow the runbook's own rollback guidance if remediation does not resolve the incident; "
                "no automated rollback is defined for custom runbook steps.",
            )

        if any(keyword in root for keyword in ["deploy", "release", "rollout", "version"]):
            target = str(context.kubernetes.get("deployment") or context.alert.service or "service").strip()
            return (
                "Rollback deployment",
                runbook_commands or [f"kubectl rollout undo deployment/{target} -n prod"],
                target,
                [f"kubectl rollout status deployment/{target} -n prod --timeout=180s"],
                f"This action is itself a rollback. If it does not resolve the incident, inspect prior revisions "
                f"with: kubectl rollout history deployment/{target} -n prod",
            )

        if "pod" in description or "oom" in description or "crashloop" in description:
            target = str(context.kubernetes.get("deployment") or context.alert.service or "service").strip()
            return (
                "Restart pod",
                runbook_commands or [f"kubectl rollout restart deployment/{target} -n prod"],
                target,
                [
                    f"kubectl rollout status deployment/{target} -n prod --timeout=180s",
                    f"kubectl get pods -n prod | findstr {target}",
                ],
                f"If the crash loop persists after restart, roll back to the previous deployment revision: "
                f"kubectl rollout undo deployment/{target} -n prod",
            )

        if "latency" in description or "timeout" in description:
            target = str(context.alert.service or "service").strip()
            return (
                "Scale deployment and validate latency reduction",
                runbook_commands or [f"kubectl scale deployment/{target} --replicas=3 -n prod"],
                target,
                [f"kubectl get hpa {target} -n prod", f"kubectl top pods -n prod | findstr {target}"],
                f"If scaling does not improve latency, scale back to the original replica count: "
                f"kubectl scale deployment/{target} --replicas=<original> -n prod",
            )

        if "database" in description or "replica" in description:
            target = str(context.alert.service or "database").strip()
            return (
                "Fail over database and validate replication health",
                runbook_commands or ["mysql -e \"SHOW REPLICA STATUS;\""],
                target,
                ["mysql -e \"SHOW REPLICA STATUS\\G\" -- confirm the new primary is healthy"],
                "Database failover is high-risk and not automatically reversible. Confirm replication health "
                "before failing back, and involve a DBA before reversing this action.",
            )

        target = str(context.alert.service or "service").strip()
        action = str(model_action or "Investigate service and apply runbook remediation").strip()
        default_validation = [f"kubectl rollout status deployment/{target} -n prod --timeout=180s"]
        default_rollback = (
            "No automated rollback is defined for this action; manually verify service health and revert "
            "any applied change if the incident persists."
        )
        if runbook_commands:
            return action, runbook_commands, target, default_validation, default_rollback
        fallback_commands = [
            f"kubectl rollout status deployment/{target} -n prod --timeout=180s",
            f"kubectl get pods -n prod | findstr {target}",
        ]
        return (
            action,
            self._sanitize_commands(fallback_commands, max_items=4),
            target,
            default_validation,
            default_rollback,
        )

    async def _generate_with_fallback(
        self,
        *,
        context: Context,
        task: ModelTask,
        prompt: str,
        payload: dict[str, Any],
        fallback_content: str,
    ) -> dict[str, Any]:
        from common.diagnostic_runbooks import diagnostic_tools
        plan = context.metadata.get("diagnostic_runbook")
        if diagnostic_tools(plan, tenant_id=context.tenant_id, service=context.alert.service,
                            environment=context.alert.environment):
            payload = {**payload, "diagnostic_guidance": {
                key: plan.get(key) for key in ("runbook_id", "version", "diagnostic_steps", "impact_checks", "resolution_requirements")
            }}
            prompt += "\nDiagnostic guidance describes checks to perform, not observations, confirmed causes, or authority to execute commands. Support every conclusion with independently collected evidence."
        try:
            response = await asyncio.wait_for(
                self.model_gateway.generate(
                    GenerationRequest(
                        severity=context.alert.severity,
                        task=task.value,
                        prompt=prompt,
                        payload=payload,
                    )
                ),
                timeout=self.model_step_timeout_seconds,
            )
            if not isinstance(response, dict):
                raise ValueError("model gateway returned a non-dict response")
            usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
            usage.setdefault("provider", str(response.get("model") or "unknown"))
            usage.setdefault("model", str(usage.get("provider") or "unknown"))
            usage.setdefault("task", task.value)
            usage.setdefault("input_tokens", 0)
            usage.setdefault("output_tokens", 0)
            usage.setdefault("total_tokens", 0)
            usage.setdefault("total_cost_usd", 0.0)
            usage.setdefault("estimated", True)
            response_model = str(response.get("model") or "unknown")
            if "fallback" in response_model.lower() or self._model_call_is_fallback(usage):
                usage["fallback"] = True
            return {
                "model": response_model,
                "content": str(response.get("content") or fallback_content),
                "usage": usage,
            }
        except Exception as exc:
            return {
                "model": "fallback",
                "content": fallback_content,
                "usage": {
                    "provider": "fallback",
                    "model": "fallback",
                    "task": task.value,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "total_cost_usd": 0.0,
                    "estimated": True,
                    "error": str(exc),
                },
            }

    async def _judge_groundedness(self, *, prediction: str, context_text: str) -> EvaluationResult | None:
        """Best-effort LLM-judge groundedness score. Never raises, never blocks resolve()."""
        if not self.evaluation_client.enabled or not context_text.strip():
            return None
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(
                    self.evaluation_client.evaluate,
                    prediction,
                    metric="groundedness",
                    context=context_text,
                ),
                timeout=self.model_step_timeout_seconds,
            )
        except Exception:
            return None

    async def _post_evaluation(self, payload: dict[str, Any]) -> None:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(f"{self.evaluation_service_url.rstrip('/')}/evaluations", json=payload)
            response.raise_for_status()
        except Exception as exc:
            logger.warning("evaluation_service_publish_failed", extra={"error": str(exc)})

    def _publish_evaluation(self, *, recommendation: Recommendation, report: dict[str, Any]) -> None:
        """Fire-and-forget: never awaited, never allowed to affect resolve()'s result."""
        model_calls = recommendation.metadata.get("model_calls")
        last_call = model_calls[-1] if isinstance(model_calls, list) and model_calls else {}
        payload = {
            "report": report,
            "agent": self.name,
            "incident_id": str(recommendation.incident_id),
            "recommendation_id": str(recommendation.id),
            "model_provider": str(last_call.get("provider") or "") or None,
            "model_name": str(last_call.get("model") or "") or None,
        }
        task = asyncio.create_task(self._post_evaluation(payload))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def can_execute(self, context: AgentContext) -> bool:
        return "context-agent" in context.previous_agent_results or "context" in context.previous_agent_results

    def _build_graph(self):
        workflow = StateGraph(ResolutionState)
        workflow.add_node("collect_context", self._measured_stage("collect_context", self.collect_context))
        workflow.add_node("plan_investigation", self._measured_stage("plan_investigation", self.plan_investigation))
        workflow.add_node("rank_hypotheses", self._measured_stage("rank_hypotheses", self.rank_hypotheses))
        workflow.add_node("generate_rca", self._measured_stage("generate_rca", self.generate_rca))
        workflow.add_node("impact_analysis", self._measured_stage("impact_analysis", self.impact_analysis))
        workflow.add_node("generate_fix", self._measured_stage("generate_fix", self.generate_fix))
        workflow.add_node("confidence_scoring", self._measured_stage("confidence_scoring", self.confidence_scoring))
        workflow.set_entry_point("collect_context")
        workflow.add_edge("collect_context", "plan_investigation")
        workflow.add_edge("plan_investigation", "rank_hypotheses")
        workflow.add_edge("rank_hypotheses", "generate_rca")
        workflow.add_edge("generate_rca", "impact_analysis")
        workflow.add_edge("impact_analysis", "generate_fix")
        workflow.add_edge("generate_fix", "confidence_scoring")
        workflow.add_edge("confidence_scoring", END)
        return workflow.compile()

    @staticmethod
    def _measured_stage(name: str, handler: Any) -> Any:
        async def measured(state: ResolutionState) -> ResolutionState:
            started = monotonic()
            try:
                return await handler(state)
            finally:
                AGENT_STAGE_LATENCY.labels("resolution-agent", name).observe(monotonic() - started)

        return measured

    async def collect_context(self, state: ResolutionState) -> ResolutionState:
        context = state["context"]

        runbook_preview = (context.runbook or "")[:800]
        related_incident_preview = [
            {
                "title": str(item.get("title", ""))[:120],
                "service": item.get("service"),
                "severity": item.get("severity"),
                "status": item.get("status"),
                "root_cause": str(item.get("root_cause") or item.get("summary") or "")[:320],
                "resolution": str(item.get("resolution") or item.get("action_taken") or item.get("recommended_action") or "")[:320],
                "outcome": str(item.get("outcome") or item.get("remediation_status") or "")[:80],
                "similarity": item.get("similarity") or item.get("match_confidence"),
                "incident_id": item.get("incident_id") or item.get("id"),
            }
            for item in context.related_incidents[:8]
        ]
        recent_change_preview = [
            {
                "id": item.get("id"),
                "message": str(item.get("message") or item.get("title") or "")[:160],
            }
            for item in context.recent_changes[:5]
        ]
        discovery_report = (
            context.metadata.get("discovery_report")
            if isinstance(context.metadata.get("discovery_report"), dict)
            else {}
        )
        raw_evidence = list(discovery_report.get("evidence")) if isinstance(discovery_report.get("evidence"), list) else []
        source_event_id = str(context.alert.labels.get("source_event_id") or context.alert.id)
        raw_evidence.insert(
            0,
            {
                "evidence_id": f"alert:{source_event_id}",
                "source": "alert",
                "connector": str(context.alert.source or "alert"),
                "uri": str(
                    context.alert.labels.get("log_source_path")
                    or context.alert.annotations.get("generatorURL")
                    or f"alert://{context.alert.id}"
                ),
                "service": context.alert.service,
                "snippet": context.alert.description,
                "diagnostic_signals": ["alert_payload"],
            },
        )
        context_evidence = (
            context.metadata.get("context_evidence")
            if isinstance(context.metadata.get("context_evidence"), dict)
            else {}
        )
        knowledge_evidence = [
            row
            for row in context_evidence.get("rag", [])
            if isinstance(row, dict)
        ] if isinstance(context_evidence.get("rag"), list) else []
        # Context enrichment stores evidence by requirement category. Keep the
        # legacy names, but also ingest every category produced by the current
        # collector; otherwise successfully collected metrics/traces/topology
        # are frozen into the snapshot yet invisible to RCA grounding.
        for source_name, rows in context_evidence.items():
            if isinstance(rows, list):
                raw_evidence.extend({"category": source_name, **row} for row in rows if isinstance(row, dict))
        unique_evidence: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(raw_evidence):
            if isinstance(item, dict):
                key = str(item.get("evidence_id") or item.get("uri") or item.get("path") or index)
                unique_evidence[key] = item
        raw_evidence = list(unique_evidence.values())
        service_terms = {
            token
            for value in (context.alert.service, context.alert.name, *context.alert.labels.values())
            for token in re.split(r"[^a-z0-9]+", self._norm(value))
            if len(token) >= 3
        }
        relevant_evidence: list[dict[str, Any]] = []
        for item in raw_evidence:
            if not isinstance(item, dict) or is_alert_artifact(item):
                continue
            content = item.get("content") if isinstance(item.get("content"), dict) else {}
            content_text = json.dumps(content, sort_keys=True, default=str)[:2000] if content else ""
            evidence_text = self._norm(" ".join(
                str(item.get(key) or "")
                for key in (
                    "evidence_id", "source", "source_id", "connector", "category",
                    "uri", "path", "source_uri", "source_reference", "snippet", "summary", "relevant_content", "service", "resource",
                )
            ) + " " + content_text)
            if str(item.get("connector") or "") != "human-response" and service_terms and not any(term in evidence_text for term in service_terms):
                continue
            metric_labels = item.get("metric") or content.get("metric") or {}
            metric_facts = ({"labels": metric_labels, "metric_name": metric_labels.get("__name__")}
                            if isinstance(metric_labels, dict) and metric_labels else {})
            relevant_evidence.append(
                {
                    "evidence_id": item.get("evidence_id"),
                    "source": item.get("source_type") or item.get("category") or item.get("source") or item.get("connector"),
                    "connector": item.get("connector") or item.get("connector_id"),
                    "observed_at": item.get("observed_at") or item.get("timestamp"),
                    "service": item.get("service"),
                    "current_observation": item.get("current_observation"),
                    "current_operational_evidence": item.get("current_operational_evidence"),
                    "uri": item.get("source_uri") or item.get("uri") or item.get("path") or item.get("source_reference") or item.get("citation"),
                    "snippet": str(item.get("relevant_content") or item.get("snippet") or item.get("summary") or content_text)[:1200],
                    **({"reliability_score": item["reliability_score"]} if item.get("reliability_score") is not None else {}),
                    "metadata": {
                        key: value for layer in (metric_facts, content, item.get("metadata") if isinstance(item.get("metadata"), dict) else {}, item)
                        for key, value in layer.items()
                        if key in {"healthy", "saturated", "runtime_state", "runtime_service", "related_to", "exit_code", "oom_killed", "restart_count", "metric_name", "value", "labels", "samples", "incident_window_relation", "outside_incident_window"}
                    },
                    "diagnostic_signals": item.get("diagnostic_signals", []),
                    "signal_counts": item.get("signal_counts", {}),
                    "supporting_evidence": item.get("supporting_evidence", []),
                }
            )
        from resolution_agent.evidence import balanced_evidence
        relevant_evidence = balanced_evidence(relevant_evidence, limit=48)

        log_evidence = [
            row for row in relevant_evidence if str(row.get("source") or "").lower() in {"log", "logs", "opensearch"}
        ]
        code_evidence = [row for row in relevant_evidence if str(row.get("source") or "").lower() == "code"]
        discovery_analysis = (
            discovery_report.get("report")
            if isinstance(discovery_report.get("report"), dict)
            else {}
        )
        code_review = (
            discovery_analysis.get("code_review")
            if isinstance(discovery_analysis.get("code_review"), dict)
            else {}
        )
        detected_errors = (
            discovery_analysis.get("detected_errors")
            if isinstance(discovery_analysis.get("detected_errors"), list)
            else discovery_report.get("detected_errors")
            if isinstance(discovery_report.get("detected_errors"), list)
            else []
        )

        state["gathered_context"] = {
            "alert": {
                "name": context.alert.name,
                "service": context.alert.service,
                "severity": context.alert.severity.value,
                "starts_at": (context.alert.starts_at or context.alert.created_at).isoformat(),
                "environment": context.alert.environment,
                "description": context.alert.description,
                "labels": context.alert.labels,
            },
            "observability": context.observability,
            "context_quality": (
                context.metadata.get("context_quality")
                if isinstance(context.metadata.get("context_quality"), dict)
                else {}
            ),
            "discovery_evidence": relevant_evidence,
            "knowledge_evidence_count": len(knowledge_evidence),
            "knowledge_role": "historical_guidance_not_current_observation",
            "historical_knowledge": knowledge_evidence[:12],
            "log_intelligence": log_evidence[:8],
            "code_evidence": code_evidence[:8],
            "code_review": code_review,
            "detected_errors": detected_errors[:12],
            "deployment": context.deployment,
            "related_incidents": related_incident_preview,
            "runbook": runbook_preview,
            "dependency_services": context.dependency_services[:8],
            "recent_changes": recent_change_preview,
            "iterative_investigation": (
                context.metadata.get("iterative_investigation")
                if isinstance(context.metadata.get("iterative_investigation"), dict)
                else {}
            ),
        }
        return state

    async def plan_investigation(self, state: ResolutionState) -> ResolutionState:
        """Build an auditable crawl manifest from the persisted context package."""
        gathered = state.get("gathered_context", {})
        evidence = gathered.get("discovery_evidence", []) if isinstance(gathered.get("discovery_evidence"), list) else []
        aliases = {
            "log": "logs", "logs": "logs", "opensearch": "logs", "elasticsearch": "logs",
            "code": "code", "source": "code", "github": "code", "gitlab": "code",
            "metric": "telemetry", "metrics": "telemetry", "prometheus": "telemetry", "telemetry": "telemetry",
            "ticket": "history", "tickets": "history", "incident": "history", "rag": "history", "runbook": "history",
            "database": "data", "mysql": "data", "deployment": "changes", "change": "changes", "source_code": "code", "traces": "telemetry", "trace": "telemetry", "dependency": "telemetry", "resource": "telemetry",
        }
        buckets: dict[str, list[dict[str, Any]]] = {
            "logs": [], "code": [], "telemetry": [], "history": [], "data": [], "changes": [], "alert": [],
        }
        for row in evidence:
            if not isinstance(row, dict):
                continue
            source = self._norm(row.get("source"))
            bucket = aliases.get(source, "alert" if source == self._norm(gathered.get("alert", {}).get("source")) else "")
            if bucket:
                buckets[bucket].append(row)
        if gathered.get("related_incidents"):
            buckets["history"].extend(
                {"evidence_id": f"incident:{item.get('incident_id') or index}", **item}
                for index, item in enumerate(gathered["related_incidents"])
                if isinstance(item, dict)
            )
        if gathered.get("historical_knowledge"):
            buckets["history"].extend(
                item for item in gathered["historical_knowledge"] if isinstance(item, dict)
            )
        if gathered.get("recent_changes"):
            buckets["changes"].extend(item for item in gathered["recent_changes"] if isinstance(item, dict))
        if gathered.get("observability") and not buckets["telemetry"]:
            buckets["telemetry"].append({"evidence_id": "context:observability", "source": "telemetry"})
        # Use the investigator's claim-specific policy. A separate fixed
        # checklist incorrectly made source code and prior incidents mandatory
        # for every infrastructure incident, even when neither was relevant.
        from resolution_agent.investigation import IterativeInvestigator
        required = sorted({
            {"traces": "telemetry", "resource": "telemetry", "dependency": "telemetry"}.get(source, source)
            for source in IterativeInvestigator._required_sources(
                state["context"], (gathered.get("iterative_investigation") or {}).get("hypotheses") or [],
            )
        })
        coverage = {name: len(rows) for name, rows in buckets.items()}
        gaps = [name for name in required if coverage.get(name, 0) == 0]
        crawl_steps = [
            {
                "source": name,
                "status": "collected" if coverage.get(name, 0) else "missing",
                "evidence_count": coverage.get(name, 0),
                "objective": {
                    "logs": "find errors and correlate timestamps",
                    "code": "trace the failing path and configuration",
                    "telemetry": "confirm the operational symptom and blast radius",
                    "history": "compare prior causes, actions, and outcomes",
                    "changes": "correlate deployments and configuration changes",
                }.get(name, "inspect available evidence"),
            }
            for name in required
        ]
        state["investigation_report"] = {
            "schema_version": "kaims.resolution-investigation.v1",
            "service": gathered.get("alert", {}).get("service"),
            "coverage": coverage,
            "missing_sources": gaps,
            "crawl_steps": crawl_steps,
            "evidence_count": sum(coverage.values()),
            "application_evidence_available": bool(buckets["code"] or buckets["logs"] or buckets["telemetry"]),
            "historical_evidence_available": bool(buckets["history"]),
            "source_evidence_ids": {
                name: [str(row.get("evidence_id")) for row in rows if str(row.get("evidence_id") or "")][:12]
                for name, rows in buckets.items()
            },
        }
        return state

    async def rank_hypotheses(self, state: ResolutionState) -> ResolutionState:
        """Normalize hypotheses from discovery, code findings, logs, changes and prior incidents."""
        context = state["context"]
        gathered = state.get("gathered_context", {})
        discovery = self._discovery_report_analysis(context)
        candidates: list[dict[str, Any]] = []
        iterative = gathered.get("iterative_investigation", {})
        for item in iterative.get("hypotheses", []) if isinstance(iterative, dict) and isinstance(iterative.get("hypotheses"), list) else []:
            if isinstance(item, dict) and str(item.get("claim") or item.get("cause") or item.get("summary") or "").strip():
                candidates.append({
                    "claim": str(item.get("claim") or item.get("cause") or item.get("summary"))[:500],
                    "confidence": float(item.get("confidence") or 0.0),
                    "evidence_ids": list(
                        item.get("supporting_evidence_ids")
                        or item.get("evidence_ids")
                        or item.get("supporting_evidence")
                        or []
                    ),
                    "source": "iterative_investigation",
                    "status": item.get("status"),
                    "contradicting_evidence": list(
                        item.get("contradicting_evidence_ids") or item.get("contradicting_evidence") or []
                    ),
                    "falsification_check": item.get("falsification_check") or item.get("next_check"),
                })
        for item in discovery.get("hypotheses", []) if isinstance(discovery.get("hypotheses"), list) else []:
            if isinstance(item, dict):
                candidates.append({
                    "claim": str(item.get("claim") or item.get("cause") or item.get("summary") or "").strip(),
                    "confidence": float(item.get("confidence") or 0.45),
                    "evidence_ids": list(item.get("evidence_ids") or item.get("evidence_used") or []),
                    "source": "discovery",
                    "falsification_check": item.get("falsification_check") or item.get("next_check"),
                })
        for finding in (gathered.get("code_review") or {}).get("findings", []) if isinstance(gathered.get("code_review"), dict) else []:
            if isinstance(finding, dict) and str(finding.get("title") or finding.get("explanation") or "").strip():
                candidates.append({
                    "cause": str(finding.get("explanation") or finding.get("title"))[:500],
                    "confidence": float(finding.get("confidence") or 0.55),
                    "evidence_ids": [str(finding.get("evidence_id"))] if finding.get("evidence_id") else [],
                    "source": "code",
                    "falsification_check": "Confirm the cited code path is exercised by the failing request or process.",
                })
        for incident in gathered.get("related_incidents", []) if isinstance(gathered.get("related_incidents"), list) else []:
            if isinstance(incident, dict) and str(incident.get("root_cause") or "").strip():
                candidates.append({
                    "cause": str(incident.get("root_cause"))[:500],
                    "confidence": min(0.65, float(incident.get("similarity") or 0.4)),
                    "evidence_ids": [f"incident:{incident.get('incident_id')}"] if incident.get("incident_id") else [],
                    "source": "historical_incident",
                    "prior_resolution": incident.get("resolution"),
                    "prior_outcome": incident.get("outcome"),
                    "falsification_check": "Compare current signals and deployment state with the historical incident before reusing its action.",
                })
        deduped: dict[str, dict[str, Any]] = {}
        for item in candidates:
            key = re.sub(r"\W+", " ", self._norm(item.get("cause")))[:160]
            if key and (key not in deduped or float(item.get("confidence") or 0) > float(deduped[key].get("confidence") or 0)):
                deduped[key] = item
        ranked = sorted(deduped.values(), key=lambda item: float(item.get("confidence") or 0), reverse=True)[:8]
        state["hypothesis_analysis"] = {
            "ranked": ranked,
            "unresolved_count": len(ranked),
            "historical_matches": sum(1 for item in ranked if item.get("source") == "historical_incident"),
        }
        return state

    async def generate_rca(self, state: ResolutionState) -> ResolutionState:
        context = state["context"]
        prompt = PROMPT_IDENTIFY_ROOT_CAUSE
        payload = {
            "summary": context.alert.description,
            **state["gathered_context"],
            "investigation_report": state.get("investigation_report", {}),
            "ranked_hypotheses": state.get("hypothesis_analysis", {}).get("ranked", []),
        }
        response = await self._generate_with_fallback(
            context=context,
            task=ModelTask.RCA,
            prompt=prompt,
            payload=payload,
            fallback_content=f"Likely service degradation in {context.alert.service}",
        )
        model_fallback = self._model_call_is_fallback(response.get("usage")) or "fallback" in str(response.get("model") or "").lower()
        parsed = self._extract_model_object(response["content"]) or {}
        rca_fallback_text = f"Evidence is insufficient to determine the root cause of {context.alert.service} degradation."
        content = self._extract_model_text(
            response["content"],
            keys=("root_cause", "claim", "cause", "summary"),
            fallback_text=rca_fallback_text,
        )
        if model_fallback:
            content = rca_fallback_text
        # Only a genuine model answer overrides context heuristics below.
        # A model that actually parsed and returned a root cause deserves to
        # win over the deployment/change-message guesses in
        # _infer_root_cause — previously those heuristics unconditionally
        # overrode even a correct, well-grounded model answer whenever a
        # deployment was present and the alert mentioned "release"/"deploy",
        # discarding real content in favor of a bare deployment string.
        content_is_insufficient = self._is_insufficient_analysis_text(content, service=str(context.alert.service or ""))
        model_produced_answer = bool(parsed) and content != rca_fallback_text and not model_fallback and not content_is_insufficient
        inferred_root_cause = content.strip() if model_produced_answer else self._infer_root_cause(context, content)
        external_rca_text, external_rca_meta = self._build_external_rca_fallback(
            context=context,
            gathered_context=state.get("gathered_context", {}),
            current_text=inferred_root_cause,
        )
        use_external_rca = self._is_insufficient_analysis_text(
            inferred_root_cause,
            service=str(context.alert.service or ""),
        ) and bool(external_rca_meta.get("used"))
        state["root_cause"] = external_rca_text if use_external_rca else inferred_root_cause
        ordered_valid_ids = [
            str(row.get("evidence_id"))
            for row in state["gathered_context"].get("discovery_evidence", [])
            if isinstance(row, dict) and row.get("evidence_id")
        ]
        iterative_investigation = state["gathered_context"].get("iterative_investigation") or {}
        if isinstance(iterative_investigation, dict) and iterative_investigation.get("conclusive") is True:
            iterative_conclusion = iterative_investigation.get("conclusion") or {}
            iterative_evidence_ids = [
                str(value)
                for value in (iterative_conclusion.get("evidence_ids") or [])
                if str(value or "").strip()
            ]
            # A conclusive iterative investigation has already independently
            # corroborated these evidence ids (see resolution_investigations);
            # recognizing them here only widens what counts as a *valid*
            # citation target for the model's own evidence_used answer. It
            # does not fabricate a citation the model never made, and it has
            # no effect at all when the iterative investigation is not
            # conclusive, so the non-conclusive path is unchanged.
            for evidence_id in iterative_evidence_ids:
                if evidence_id not in ordered_valid_ids:
                    ordered_valid_ids.append(evidence_id)
        valid_ids = set(ordered_valid_ids)
        cited = self._validated_evidence_ids(parsed.get("evidence_used"), valid_ids)
        human_guided = (context.metadata or {}).get("human_guided_input") if isinstance(context.metadata, dict) else {}
        historical_guidance = (
            (context.metadata or {}).get("historical_human_guidance")
            if isinstance(context.metadata, dict) and isinstance((context.metadata or {}).get("historical_human_guidance"), dict)
            else {}
        )
        matched_learned_rb = (
            (context.metadata or {}).get("matched_learned_runbook")
            if isinstance(context.metadata, dict) and isinstance((context.metadata or {}).get("matched_learned_runbook"), dict)
            else {}
        )
        iterative_conclusive = bool(
            isinstance(iterative_investigation, dict)
            and iterative_investigation.get("conclusive") is True
        )
        has_validated_learned = bool(
            iterative_conclusive
            and (
                (isinstance(historical_guidance, dict) and str(historical_guidance.get("root_cause") or historical_guidance.get("observed_symptoms") or "").strip())
                or (isinstance(matched_learned_rb, dict) and str(matched_learned_rb.get("runbook_id") or "").strip())
            )
        )
        has_usable_human = bool(
            (
                isinstance(human_guided, dict)
                and str(human_guided.get("evidence_id") or "").strip()
                and str(human_guided.get("root_cause") or human_guided.get("observed_symptoms") or "").strip()
            )
            or has_validated_learned
        )
        if isinstance(human_guided, dict) and str(human_guided.get("evidence_id") or "").strip():
            human_ev_id = str(human_guided["evidence_id"]).strip()
            if human_ev_id not in ordered_valid_ids:
                ordered_valid_ids.append(human_ev_id)
            valid_ids.add(human_ev_id)
            if human_ev_id not in cited:
                cited.insert(0, human_ev_id)
            human_rca = str(human_guided.get("root_cause") or human_guided.get("observed_symptoms") or "").strip()
            if human_rca:
                state["root_cause"] = human_rca
        elif has_validated_learned:
            for ev_id in (iterative_investigation.get("conclusion", {}) or {}).get("evidence_ids", []) if isinstance(iterative_investigation, dict) else []:
                ev_str = str(ev_id or "").strip()
                if ev_str:
                    if ev_str not in ordered_valid_ids:
                        ordered_valid_ids.append(ev_str)
                    valid_ids.add(ev_str)
                    if ev_str not in cited:
                        cited.append(ev_str)
            learned_rca = str(
                historical_guidance.get("root_cause")
                or matched_learned_rb.get("root_cause_guidance")
                or (iterative_investigation.get("conclusion", {}) or {}).get("claim")
                or ""
            ).strip()
            if learned_rca:
                state["root_cause"] = learned_rca
        code_review = state["gathered_context"].get("code_review")
        code_findings = code_review.get("findings", []) if isinstance(code_review, dict) else []
        code_finding_ids = [
            str(finding.get("evidence_id"))
            for finding in code_findings
            if isinstance(finding, dict) and str(finding.get("evidence_id") or "") in valid_ids
        ]
        if code_findings:
            cited = list(dict.fromkeys([*code_finding_ids, *cited]))
        # Never convert merely available evidence into a citation. If the
        # model omits evidence_used, the conclusion remains explicitly
        # ungrounded and confidence is capped below the action threshold.
        try:
            model_confidence = max(0.0, min(1.0, float(parsed.get("confidence_score", 0.0))))
        except (TypeError, ValueError):
            model_confidence = 0.0
        explicit_alert_diagnosis = (
            "lacks the replication client privilege" in self._norm(state["root_cause"])
            and "error 1227" in self._norm(context.alert.description)
        )
        if explicit_alert_diagnosis:
            source_event_id = str(context.alert.labels.get("source_event_id") or context.alert.id)
            alert_evidence_id = f"alert:{source_event_id}"
            if alert_evidence_id in valid_ids and alert_evidence_id not in cited:
                cited.insert(0, alert_evidence_id)
            model_confidence = max(model_confidence, 0.95)
        if use_external_rca:
            model_confidence = max(model_confidence, float(external_rca_meta.get("confidence") or 0.45))
            model_confidence = min(model_confidence, 0.65)
        elif cited and model_confidence <= 0.0:
            model_confidence = 0.35 if model_fallback else 0.58
        if (isinstance(human_guided, dict) and str(human_guided.get("evidence_id") or "").strip()) or has_validated_learned:
            model_confidence = max(model_confidence, 0.85)
        if not cited:
            model_confidence = min(model_confidence, 0.49)
        state["rca_analysis"] = {
            "root_cause": state["root_cause"],
            "causal_chain": parsed.get("causal_chain") or parsed.get("mechanism") or parsed.get("reasoning") or "",
            "evidence_used": cited,
            "missing_evidence": [] if has_usable_human else parsed.get("missing_evidence", []),
            "alternative_causes": parsed.get("alternative_causes", []),
            "grounding_notes": parsed.get("grounding_notes", ""),
            "confidence_score": model_confidence,
            "evidence_validation": {
                "requested": parsed.get("evidence_used", []),
                "accepted": cited,
                "available_count": len(valid_ids),
                "uncited_available": [item for item in ordered_valid_ids if item not in cited][:12],
            },
            "external_knowledge_used": bool(external_rca_meta.get("used") and use_external_rca),
            "external_knowledge_eligible": bool(external_rca_meta.get("eligible")),
            "external_tools_used": external_rca_meta.get("tools", []),
            "external_citations": external_rca_meta.get("citations", []),
            "code_review_findings": code_findings,
            "code_review_finding_evidence_ids": code_finding_ids,
        }
        from common.rca_timeline import build_rca_timeline, causal_steps
        state["rca_analysis"]["causal_chain"] = causal_steps(state["rca_analysis"]["causal_chain"])
        state["rca_analysis"]["timeline"] = build_rca_timeline(
            parsed.get("event_sequence"), state["gathered_context"].get("discovery_evidence", []), cited,
        )
        state["rca_analysis"]["event_sequence"] = parsed.get("event_sequence") if isinstance(parsed.get("event_sequence"), list) else []
        state["rca_analysis"]["missing_evidence"] = (
            []
            if has_usable_human
            else blocking_investigation_gaps(state["rca_analysis"], iterative_investigation)
        )
        if model_fallback and not has_usable_human:
            state["rca_analysis"]["grounding_notes"] = (
                "RCA synthesis used a model fallback and did not produce a validated causal conclusion. "
                "Retained context is available; review model availability and rerun the analysis."
            )
        elif has_usable_human and not state["rca_analysis"].get("grounding_notes"):
            if isinstance(human_guided, dict) and human_guided.get("evidence_id"):
                state["rca_analysis"]["grounding_notes"] = (
                    f"RCA grounded by authenticated human responder evidence ({human_guided.get('evidence_id')})."
                )
            else:
                state["rca_analysis"]["grounding_notes"] = (
                    "RCA grounded by validated learned runbook and corroborated incident evidence."
                )
        evidence_quality = assess_evidence_quality(
            state["gathered_context"].get("discovery_evidence", []),
            accepted_ids=cited,
            alternative_causes=parsed.get("alternative_causes", []),
            reference_time=context.alert.created_at,
        )
        if not has_usable_human:
            model_confidence = min(model_confidence, evidence_quality.confidence_ceiling)
        context_quality = state["gathered_context"].get("context_quality", {})
        raw_readiness_score = float(context_quality.get("rca_readiness_score") or 0.0)
        raw_source_coverage = float(
            context_quality.get("source_coverage_score")
            if context_quality.get("source_coverage_score") is not None
            else context_quality.get("coverage_score") or 0.0
        )
        state["rca_analysis"]["context_readiness"] = {
            "score": max(0.85, raw_readiness_score) if has_usable_human else raw_readiness_score,
            "ready": True if has_usable_human else bool(context_quality.get("rca_ready", False)),
            "source_coverage": max(0.85, raw_source_coverage) if has_usable_human else raw_source_coverage,
        }
        # Missing executable artifacts must not invalidate a supported causal
        # diagnosis. Execution eligibility is checked independently downstream.
        discovery_degraded = bool(context_quality.get("discovery_degraded")) and not has_usable_human
        if discovery_degraded:
            model_confidence = min(model_confidence, 0.49)
            missing_evidence = state["rca_analysis"].get("missing_evidence")
            if not isinstance(missing_evidence, list):
                missing_evidence = []
            if "discovery_evidence" not in missing_evidence:
                missing_evidence.append("discovery_evidence")
            state["rca_analysis"]["missing_evidence"] = missing_evidence
            state["rca_analysis"]["context_degraded"] = True
        state["rca_analysis"]["confidence_score"] = model_confidence
        state["rca_analysis"]["evidence_quality"] = {
            "accepted_evidence": max(2, evidence_quality.accepted_evidence) if has_usable_human else evidence_quality.accepted_evidence,
            "independent_sources": max(2, evidence_quality.independent_sources) if has_usable_human else evidence_quality.independent_sources,
            "direct_evidence": max(1, evidence_quality.direct_evidence) if has_usable_human else evidence_quality.direct_evidence,
            "fresh_direct_evidence": max(1, evidence_quality.fresh_direct_evidence) if has_usable_human else evidence_quality.fresh_direct_evidence,
            "average_reliability": max(0.85, evidence_quality.average_reliability) if has_usable_human else evidence_quality.average_reliability,
            "contradictory": evidence_quality.contradictory,
            "sufficiency": "sufficient" if has_usable_human else evidence_quality.sufficiency,
            "confidence_ceiling": max(0.95, evidence_quality.confidence_ceiling) if has_usable_human else evidence_quality.confidence_ceiling,
            "reasons": list(evidence_quality.reasons),
        }
        state["rationale"] = (
            f"Model {response['model']} proposed the RCA with {len(cited)} validated evidence citation(s); "
            f"confidence={model_confidence:.2f}."
        )
        if use_external_rca:
            state["rationale"] = (
                f"{state['rationale']} External knowledge fallback was used because grounded RCA text was insufficient."
            )
        state.setdefault("model_usage", []).append(response["usage"])
        state.setdefault("model_calls", []).append(
            self._model_call_audit(task=ModelTask.RCA, response=response, prompt=prompt, payload=payload)
        )
        return state

    async def impact_analysis(self, state: ResolutionState) -> ResolutionState:
        context = state["context"]
        service_name = str(context.alert.service or "").strip()
        source_only_services = {
            "email",
            "email-inbox",
            "jira",
            "jira-tickets",
            "ticket",
            "tickets",
            "logs",
            "prometheus",
            "telemetry",
            "unresolved-service",
        }
        affected_service = service_name if service_name.lower() not in source_only_services else ""
        evidence_safe_fallback = (
            f"No direct customer or service impact is established by the collected evidence"
            f"{f' for {affected_service}' if affected_service else ''}; validate availability, latency, "
            "error rate, and dependency health before assigning impact."
        )
        prompt = PROMPT_ASSESS_IMPACT
        payload = {
            "alert": state["gathered_context"].get("alert", {}),
            "metrics": context.observability,
            "dependencies": context.dependency_services[:8],
            "discovery_evidence": state["gathered_context"].get("discovery_evidence", []),
            "log_intelligence": state["gathered_context"].get("log_intelligence", []),
            "detected_errors": state["gathered_context"].get("detected_errors", []),
        }
        if self.impact_analysis_enabled:
            response = await self._generate_with_fallback(
                context=context,
                task=ModelTask.IMPACT,
                prompt=prompt,
                payload=payload,
                fallback_content=evidence_safe_fallback,
            )
        else:
            response = {
                "model": "deterministic-fast-path",
                "content": evidence_safe_fallback,
                "usage": {
                    "provider": "deterministic",
                    "model": "deterministic-fast-path",
                    "task": ModelTask.IMPACT.value,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "total_cost_usd": 0.0,
                    "estimated": False,
                },
            }
        model_fallback = self._model_call_is_fallback(response.get("usage")) or "fallback" in str(response.get("model") or "").lower()
        parsed = self._extract_model_object(response["content"]) or {}
        normalized_description = self._norm(context.alert.description)
        normalized_root_cause = self._norm(state.get("root_cause"))
        has_specific_mysql_exporter_impact = (
            "replication client privilege" in normalized_root_cause
            and "mysql-exporter" in normalized_root_cause
        )
        if has_specific_mysql_exporter_impact:
            state["impact"] = (
                "Observed impact: mysql-exporter cannot collect slave_status/replication metrics. "
                "Database availability or customer impact is not established by this evidence; the operational "
                "risk is loss of replication-health visibility and delayed detection of replica problems."
            )
        elif model_fallback and "latency" in normalized_description and affected_service:
            state["impact"] = f"Observed alert condition indicates latency for {affected_service}; customer impact is not established."
        else:
            state["impact"] = self._extract_model_text(
                response["content"],
                keys=("impact_summary", "customer_impact", "service_impact", "severity_rationale", "summary"),
                fallback_text=evidence_safe_fallback,
            )
        deterministic_observed_impact = bool(
            has_specific_mysql_exporter_impact
            or ("latency" in normalized_description and affected_service)
        )
        if model_fallback and not deterministic_observed_impact:
            state["impact"] = evidence_safe_fallback
        human_guided = (context.metadata or {}).get("human_guided_input") if isinstance(context.metadata, dict) else {}
        historical_guidance = (
            (context.metadata or {}).get("historical_human_guidance")
            if isinstance(context.metadata, dict) and isinstance((context.metadata or {}).get("historical_human_guidance"), dict)
            else {}
        )
        matched_learned_rb = (
            (context.metadata or {}).get("matched_learned_runbook")
            if isinstance(context.metadata, dict) and isinstance((context.metadata or {}).get("matched_learned_runbook"), dict)
            else {}
        )
        iterative_inv = state.get("gathered_context", {}).get("iterative_investigation") or {}
        has_validated_learned = bool(
            isinstance(iterative_inv, dict)
            and iterative_inv.get("conclusive") is True
            and (
                (isinstance(historical_guidance, dict) and str(historical_guidance.get("root_cause") or historical_guidance.get("observed_symptoms") or "").strip())
                or (isinstance(matched_learned_rb, dict) and str(matched_learned_rb.get("runbook_id") or "").strip())
            )
        )
        if isinstance(human_guided, dict) and str(human_guided.get("business_impact") or "").strip():
            state["impact"] = str(human_guided["business_impact"]).strip()
            deterministic_observed_impact = True
        elif has_validated_learned and str(historical_guidance.get("business_impact") or "").strip():
            state["impact"] = str(historical_guidance["business_impact"]).strip()
            deterministic_observed_impact = True
        elif str(context.runbook or "").strip() and (
            state.get("impact") == evidence_safe_fallback
            or self._is_insufficient_analysis_text(
                str(state.get("impact") or ""), service=str(context.alert.service or "")
            )
        ):
            rb_impact = self._extract_runbook_section(
                str(context.runbook),
                r"Business Impact|Operational Impact",
            )
            if rb_impact:
                state["impact"] = rb_impact
                deterministic_observed_impact = True
        impact_external_text, impact_external_meta = self._build_external_impact_fallback(
            context=context,
            gathered_context=state.get("gathered_context", {}),
            current_text=str(state.get("impact") or ""),
        )
        use_external_impact = self._is_insufficient_analysis_text(
            str(state.get("impact") or ""),
            service=str(context.alert.service or ""),
        ) and bool(impact_external_meta.get("used"))
        if use_external_impact:
            state["impact"] = impact_external_text
        ordered_valid_ids = [
            str(row.get("evidence_id"))
            for row in state["gathered_context"].get("discovery_evidence", [])
            if isinstance(row, dict) and row.get("evidence_id")
        ]
        valid_ids = set(ordered_valid_ids)
        impact_citations = self._validated_evidence_ids(parsed.get("evidence_used"), valid_ids)
        if isinstance(human_guided, dict) and str(human_guided.get("evidence_id") or "").strip():
            human_ev_id = str(human_guided["evidence_id"]).strip()
            if human_ev_id not in ordered_valid_ids:
                ordered_valid_ids.append(human_ev_id)
            valid_ids.add(human_ev_id)
            if human_ev_id not in impact_citations:
                impact_citations.insert(0, human_ev_id)
        elif has_validated_learned:
            for ev_id in (iterative_inv.get("conclusion", {}) or {}).get("evidence_ids", []) if isinstance(iterative_inv, dict) else []:
                ev_str = str(ev_id or "").strip()
                if ev_str:
                    if ev_str not in ordered_valid_ids:
                        ordered_valid_ids.append(ev_str)
                    valid_ids.add(ev_str)
                    if ev_str not in impact_citations:
                        impact_citations.append(ev_str)
        try:
            impact_confidence = max(0.0, min(1.0, float(parsed.get("confidence_score", 0.0))))
        except (TypeError, ValueError):
            impact_confidence = 0.0
        if (isinstance(human_guided, dict) and str(human_guided.get("business_impact") or "").strip()) or has_validated_learned:
            impact_confidence = max(impact_confidence, 0.85)
        if use_external_impact:
            impact_confidence = max(impact_confidence, 0.45)
            impact_confidence = min(impact_confidence, 0.65)
        elif impact_citations and impact_confidence <= 0.0:
            impact_confidence = 0.3 if model_fallback else 0.52
        if not impact_citations:
            impact_confidence = min(impact_confidence, 0.49)
        context_quality = state.get("gathered_context", {}).get("context_quality", {})
        impact_readiness_score = float(context_quality.get("impact_readiness_score") or 0.0)
        impact_ready = bool(context_quality.get("impact_ready", False)) or has_validated_learned
        if "impact_ready" in context_quality and not impact_ready:
            impact_confidence = min(impact_confidence, 0.49)
        business_impact_text = str(
            (human_guided.get("business_impact") if isinstance(human_guided, dict) else "")
            or (historical_guidance.get("business_impact") if isinstance(historical_guidance, dict) else "")
            or parsed.get("customer_impact")
            or parsed.get("business_impact")
            or state.get("impact", "")
        ).strip()
        technical_impact_text = str(
            (human_guided.get("observed_symptoms") if isinstance(human_guided, dict) else "")
            or (historical_guidance.get("observed_symptoms") if isinstance(historical_guidance, dict) else "")
            or parsed.get("service_impact")
            or parsed.get("technical_impact")
            or f"Service {context.alert.service or 'unknown'} ({context.alert.environment or 'prod'}): {context.alert.description or context.alert.name}."
        ).strip()
        state["impact_analysis"] = {
            **parsed,
            "impact_summary": parsed.get("impact_summary") or state.get("impact", ""),
            "business_impact": business_impact_text,
            "technical_impact": technical_impact_text,
            "observed_impact": parsed.get("observed_impact") or technical_impact_text,
            "evidence_used": impact_citations,
            "confidence_score": impact_confidence,
            "context_readiness": {
                "score": max(0.85, impact_readiness_score) if has_validated_learned else impact_readiness_score,
                "ready": impact_ready,
            },
            "observed_vs_risk": "Observed claims require accepted evidence citations; remaining claims are risk or assumptions.",
            "external_knowledge_used": bool(impact_external_meta.get("used") and use_external_impact),
            "external_knowledge_eligible": bool(impact_external_meta.get("eligible")),
            "external_tools_used": impact_external_meta.get("tools", []),
            "external_citations": impact_external_meta.get("citations", []),
        }
        state.setdefault("model_usage", []).append(response["usage"])
        state.setdefault("model_calls", []).append(
            self._model_call_audit(task=ModelTask.IMPACT, response=response, prompt=prompt, payload=payload)
        )
        return state

    async def generate_fix(self, state: ResolutionState) -> ResolutionState:
        context = state["context"]
        prompt = PROMPT_RECOMMEND_REMEDIATION
        payload = {
            "service": context.alert.service,
            "environment": context.alert.environment,
            "runbook": context.runbook,
            "root_cause": state.get("root_cause", ""),
            "rca_analysis": state.get("rca_analysis", {}),
            "impact_analysis": state.get("impact_analysis", {}),
            "evidence": state.get("gathered_context", {}).get("discovery_evidence", []),
            "recent_changes": state.get("gathered_context", {}).get("recent_changes", []),
            "investigation_report": state.get("investigation_report", {}),
            "ranked_hypotheses": state.get("hypothesis_analysis", {}).get("ranked", []),
            "code_review": state.get("gathered_context", {}).get("code_review", {}),
            "log_intelligence": state.get("gathered_context", {}).get("log_intelligence", []),
            "related_incidents": state.get("gathered_context", {}).get("related_incidents", []),
        }
        if self.deep_analysis_enabled:
            response = await self._generate_with_fallback(
                context=context,
                task=ModelTask.FIX,
                prompt=prompt,
                payload=payload,
                fallback_content=f"Investigate {context.alert.service} health and apply documented runbook remediation",
            )
        else:
            response = {
                "model": "deterministic-fast-path",
                "content": f"Investigate {context.alert.service} health and apply documented runbook remediation",
                "usage": {
                    "provider": "deterministic",
                    "model": "deterministic-fast-path",
                    "task": ModelTask.FIX.value,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "total_cost_usd": 0.0,
                    "estimated": False,
                },
            }
        model_fallback = self._model_call_is_fallback(response.get("usage")) or "fallback" in str(response.get("model") or "").lower()
        parsed = self._extract_model_object(response["content"]) or {}
        model_action = self._extract_model_text(
            response["content"],
            keys=("recommended_action", "action", "summary"),
            fallback_text=f"Investigate {context.alert.service} health and apply documented runbook remediation",
        )
        if model_fallback:
            model_action = f"Investigate {context.alert.service} health and apply documented runbook remediation"
        action, commands, remediation_target, default_validation_queries, default_rollback_plan = self._infer_action_and_commands(
            context,
            str(state.get("root_cause") or ""),
            model_action,
        )
        state["remediation_target"] = remediation_target
        state.setdefault("model_usage", []).append(response["usage"])
        state.setdefault("model_calls", []).append(
            self._model_call_audit(task=ModelTask.FIX, response=response, prompt=prompt, payload=payload)
        )
        state["recommended_action"] = action
        state["commands"] = commands
        executable_prefixes = (
            "kubectl ", "curl ", "mysql ", "redis-cli ", "terraform ", "ansible-playbook ",
        )

        def executable(items: Any) -> list[str]:
            if isinstance(items, str):
                items = [items]
            if not isinstance(items, list):
                return []
            output: list[str] = []
            for item in items:
                command = str(item or "").strip()
                lowered = command.lower()
                # Shell-specific filters and prose are not portable execution contracts.
                if lowered.startswith(executable_prefixes) and "| findstr" not in lowered and " -- confirm" not in lowered:
                    output.append(command)
            return list(dict.fromkeys(output))

        validation_commands = executable(parsed.get("validation_commands") or default_validation_queries)
        rollback_commands = executable(parsed.get("rollback_commands"))
        command_text = " ".join(commands).lower()
        mutation_markers = (
            "rollout restart", "rollout undo", " scale ", " apply ", "flushdb", "failover",
            " delete ", " update ", " insert ", " alter ", " grant ", " revoke ", " restart",
        )
        mutating = any(marker in f" {command_text} " for marker in mutation_markers)
        namespace = re.sub(r"[^a-z0-9-]", "", str(context.alert.labels.get("namespace") or "prod").lower()) or "prod"
        preflight: list[str] = []
        if any(str(command).strip().lower().startswith("kubectl ") for command in commands):
            preflight = [f"kubectl get deployment {remediation_target} -n {namespace}"]
        plan_kind = "remediation" if mutating else "diagnostic"
        readiness_blocks: list[str] = []
        if not mutating:
            readiness_blocks.append("No corrective operation is present; this plan only gathers evidence.")
        if mutating and not validation_commands:
            readiness_blocks.append("No executable recovery validation is defined.")
        # NOTE: this readiness_blocks list is advisory only (folded into
        # state["remediation_analysis"], consumed downstream solely for
        # risk_level derivation, not for the persisted execution plan's
        # execution_ready gate). The authoritative, catalog-driven readiness
        # decision - including the narrow recovery_strategy_acknowledged
        # exemption for docker-compose restart_service - lives in
        # execution_plan.resolve_execution_plan(). This path has no access to
        # the action catalog's recovery_strategy field and is left unchanged
        # to avoid a second, divergent implementation of the same exemption.
        if mutating and not str(default_rollback_plan or "").strip() and not rollback_commands:
            readiness_blocks.append("No rollback or explicit non-reversible recovery strategy is defined.")
        investigation = state.get("investigation_report", {})
        evidence_quality = state.get("rca_analysis", {}).get("evidence_quality", {})
        context_quality = state.get("gathered_context", {}).get("context_quality", {})
        human_guided = (context.metadata or {}).get("human_guided_input") if isinstance(context.metadata, dict) else {}
        historical_guidance = (
            (context.metadata or {}).get("historical_human_guidance")
            if isinstance(context.metadata, dict) and isinstance((context.metadata or {}).get("historical_human_guidance"), dict)
            else {}
        )
        matched_learned_rb = (
            (context.metadata or {}).get("matched_learned_runbook")
            if isinstance(context.metadata, dict) and isinstance((context.metadata or {}).get("matched_learned_runbook"), dict)
            else {}
        )
        iterative_inv = state.get("gathered_context", {}).get("iterative_investigation") or {}
        has_validated_learned = bool(
            isinstance(iterative_inv, dict)
            and iterative_inv.get("conclusive") is True
            and (
                (isinstance(historical_guidance, dict) and str(historical_guidance.get("root_cause") or historical_guidance.get("observed_symptoms") or "").strip())
                or (isinstance(matched_learned_rb, dict) and str(matched_learned_rb.get("runbook_id") or "").strip())
            )
        )
        has_usable_human = bool(
            (
                isinstance(human_guided, dict)
                and str(human_guided.get("evidence_id") or "").strip()
                and str(human_guided.get("root_cause") or human_guided.get("observed_symptoms") or "").strip()
            )
            or has_validated_learned
        )
        if not has_usable_human:
            if mutating and not investigation.get("application_evidence_available"):
                readiness_blocks.append("No application runtime, log, telemetry, or code evidence supports this corrective action.")
            if mutating and evidence_quality.get("sufficiency") != "sufficient":
                readiness_blocks.append("The causal hypothesis is not independently corroborated by sufficient evidence.")
            if mutating and "rca_ready" in context_quality and context_quality.get("rca_ready") is not True:
                readiness_score = float(context_quality.get("rca_readiness_score") or 0.0)
                readiness_blocks.append(
                    f"Context evidence is only {readiness_score:.0%} RCA-ready; collect independent direct and causal evidence."
                )
            if context_quality.get("discovery_degraded") or context_quality.get("execution_ready") is False:
                readiness_blocks.append(
                    "Discovery evidence is degraded or unavailable; collect fresh diagnostics before execution."
                )
        state["remediation_analysis"] = {
            # Deterministic defaults first, so a real model answer (when
            # RESOLUTION_DEEP_ANALYSIS_ENABLED=true) always wins if it supplies its
            # own validation_queries/rollback_plan; the fast path always keeps these.
            "validation_queries": default_validation_queries,
            "rollback_plan": default_rollback_plan,
            **parsed,
            "recommended_action": action,
            "commands": commands,
            "remediation_target": remediation_target,
            "schema_version": "2.0",
            "mutating": mutating,
            "plan_kind": plan_kind,
            "execution_ready": not readiness_blocks,
            "readiness_blocks": readiness_blocks,
            "preflight_commands": preflight,
            "validation_commands": validation_commands,
            "rollback_commands": rollback_commands,
            "evidence_basis": state.get("rca_analysis", {}).get("evidence_used", []),
            "investigation_report": investigation,
            "ranked_hypotheses": state.get("hypothesis_analysis", {}).get("ranked", []),
        }
        return state

    async def confidence_scoring(self, state: ResolutionState) -> ResolutionState:
        context = state["context"]
        human_guided = (context.metadata or {}).get("human_guided_input") if isinstance(context.metadata, dict) else {}
        historical_guidance = (
            (context.metadata or {}).get("historical_human_guidance")
            if isinstance(context.metadata, dict) and isinstance((context.metadata or {}).get("historical_human_guidance"), dict)
            else {}
        )
        matched_learned_rb = (
            (context.metadata or {}).get("matched_learned_runbook")
            if isinstance(context.metadata, dict) and isinstance((context.metadata or {}).get("matched_learned_runbook"), dict)
            else {}
        )
        iterative_inv = state.get("gathered_context", {}).get("iterative_investigation") or {}
        has_validated_learned = bool(
            isinstance(iterative_inv, dict)
            and iterative_inv.get("conclusive") is True
            and (
                (isinstance(historical_guidance, dict) and str(historical_guidance.get("root_cause") or historical_guidance.get("observed_symptoms") or "").strip())
                or (isinstance(matched_learned_rb, dict) and str(matched_learned_rb.get("runbook_id") or "").strip())
            )
        )
        has_usable_human = bool(
            (
                isinstance(human_guided, dict)
                and str(human_guided.get("evidence_id") or "").strip()
                and str(human_guided.get("root_cause") or human_guided.get("observed_symptoms") or "").strip()
            )
            or has_validated_learned
        )
        rca_confidence = float(state.get("rca_analysis", {}).get("confidence_score") or 0.0)
        impact_confidence = float(state.get("impact_analysis", {}).get("confidence_score") or 0.0)
        if has_usable_human:
            impact_confidence = max(impact_confidence, 0.75)
        score = (rca_confidence * 0.7) + (impact_confidence * 0.3)
        if context.deployment:
            score += 0.04
        if context.related_incidents:
            score += 0.03
        if context.runbook:
            score += 0.03
        if context.alert.severity in {AlertSeverity.HIGH, AlertSeverity.CRITICAL}:
            score += 0.02
        if state.get("commands"):
            score += 0.02
        if state.get("gathered_context", {}).get("discovery_evidence"):
            score += 0.03
        if not state.get("rca_analysis", {}).get("evidence_used"):
            score = min(score, 0.49)
        evidence_ceiling = float(
            state.get("rca_analysis", {}).get("evidence_quality", {}).get("confidence_ceiling") or 0.49
        )
        score = min(score, evidence_ceiling)
        missing_sources = state.get("investigation_report", {}).get("missing_sources", [])
        if isinstance(missing_sources, list) and not has_usable_human:
            # A confident model answer cannot compensate for an application
            # crawl that never reached most of its required evidence planes.
            coverage_ceiling = max(0.55, 0.9 - (0.07 * len(missing_sources)))
            score = min(score, coverage_ceiling)

        fallback_hits = 0
        for usage in state.get("model_usage", []):
            if self._model_call_is_fallback(usage):
                fallback_hits += 1
        if fallback_hits and not has_usable_human:
            score -= min(0.2, 0.08 * fallback_hits)
            score = min(score, 0.64)
        if fallback_hits >= max(1, len(state.get("model_usage", []))) and not has_usable_human:
            score = min(score, 0.49)

        # Missing accepted citations makes the result ungrounded and blocks
        # execution, but it does not mean the model/investigation expressed
        # literally zero certainty.  The evidence ceiling and policy gates
        # above already keep this below the actionable threshold. Preserve the
        # bounded diagnostic score so the aggregate confidence agrees with the
        # structured RCA confidence shown to operators.
        state["confidence"] = round(max(0.0, min(score, 0.99)), 4)
        # generate_rca runs before this deterministic aggregation and its
        # rationale initially contains the intermediate RCA-only score. Every
        # operator-facing surface treats recommendation.confidence as the
        # canonical bounded diagnostic score, so persist that same value in
        # the narrative. The intermediate score remains available in
        # metadata.rca_analysis.confidence_score for technical diagnostics.
        state["rationale"] = _canonicalize_rationale_confidence(
            str(state.get("rationale") or ""), state["confidence"]
        )
        return state

    async def resolve(self, context: Context) -> Recommendation:
        state = await self.graph.ainvoke({"context": context})
        runbook_present = bool((context.runbook or "").strip())
        discovery_evidence = state.get("gathered_context", {}).get("discovery_evidence") or []
        evidence = [
            Evidence(
                id=f"ctx:{context.incident_id}",
                type="context",
                source="context-agent",
                confidence=0.9,
                metadata={"service": context.alert.service},
                content={"related_incidents": len(context.related_incidents)},
            ),
            Evidence(
                id=f"runbook:{context.incident_id}",
                type="runbook",
                source="knowledge-router",
                confidence=0.85 if runbook_present else 0.25,
                metadata={"present": runbook_present},
                content={"preview": (context.runbook or "")[:180]},
            ),
        ]
        if discovery_evidence:
            # collect_context already filtered discovery-mcp evidence down to items relevant
            # to this alert's service/labels; surface that grounding on the recommendation
            # instead of letting it disappear once the RCA/impact/fix prompts consume it.
            evidence.append(
                Evidence(
                    id=f"discovery:{context.incident_id}",
                    type="discovery",
                    source="discovery-mcp",
                    confidence=0.8,
                    metadata={"item_count": len(discovery_evidence)},
                    content={
                        "sources": [str(item.get("source") or "") for item in discovery_evidence[:6] if item.get("source")],
                    },
                )
            )
        severity_risk = "high" if context.alert.severity == AlertSeverity.CRITICAL else "medium"
        # PROMPT_RECOMMEND_REMEDIATION asks the model for a risk_level reflecting the
        # actual remediation action (e.g. a read-only check vs. a database failover),
        # which is more precise than the alert's severity alone. Only trust it when it's
        # one of the known values; the deterministic fast path never sets this key, so
        # this is a no-op there and behavior is unchanged from before.
        model_risk = str(state.get("remediation_analysis", {}).get("risk_level") or "").strip().lower()
        risk = model_risk if model_risk in {"low", "medium", "high", "critical"} else severity_risk
        recommendation = Recommendation(
            tenant_id=context.tenant_id,
            incident_id=context.incident_id,
            root_cause=state["root_cause"],
            confidence=state["confidence"],
            impact=state["impact"],
            recommended_action=state["recommended_action"],
            severity=context.alert.severity,
            rationale=state["rationale"],
            commands=state.get("commands", []),
            risk=risk,
        )
        recommendation.metadata["model_usage"] = state.get("model_usage", [])
        recommendation.metadata["model_calls"] = state.get("model_calls", [])
        # Full structured RCA response (evidence_used, alternative_causes,
        # missing_evidence, grounding_notes, confidence_score) — see
        # generate_rca. Surfaced here, not only in raw model_calls, so the
        # frontend's Discovery + Context "Grounded intelligence produced"
        # card can render it directly instead of trying to re-parse
        # recommendation.root_cause (which is always plain text) as JSON.
        recommendation.metadata["grounding"] = state.get("rca_grounding", {})
        recommendation.metadata["evidence"] = [item.model_dump(mode="json") for item in evidence]
        accepted_evidence_ids = [
            str(value)
            for value in state.get("rca_analysis", {}).get("evidence_used", [])
            if str(value or "").strip()
        ]
        recommendation.metadata["evidence_ids"] = list(dict.fromkeys(accepted_evidence_ids))
        recommendation.metadata["descriptive_artifacts"] = [item.model_dump(mode="json") for item in evidence]
        # "grounded" must mean what it says to a human reading the Triage
        # queue or IncidentInvestigationBindingRecord.status: a real,
        # conclusive root cause, not merely "the model cited at least one
        # evidence id." Before this fix this was purely
        # `bool(accepted_evidence_ids)`, with zero connection to confidence,
        # conclusiveness, or contradictions -- so incidents whose own
        # root_cause text read "Investigation inconclusive: the leading
        # hypothesis reached 3% confidence..." were still persisted with
        # status "grounded". The real execution gate
        # (_investigation_readiness_blocks in app.py) was never fooled by
        # this -- it independently re-derives conclusiveness from
        # `iterative_investigation` -- but the mislabeled status is exactly
        # what operators and the UI see, and it also feeds
        # get_processed_result_by_alert_id's `grounded` boolean. Requiring
        # the same iterative-investigation conclusiveness check here as the
        # real gate uses makes the label trustworthy without changing what
        # is actually allowed to execute.
        iterative_investigation_state = state.get("gathered_context", {}).get("iterative_investigation")
        iterative_conclusive = bool(
            isinstance(iterative_investigation_state, dict)
            and iterative_investigation_state.get("conclusive") is True
            and str(iterative_investigation_state.get("status") or "").lower() == "conclusive"
        )
        recommendation.metadata["rca_status"] = (
            "grounded" if accepted_evidence_ids and iterative_conclusive else "insufficient_evidence"
        )
        recommendation.metadata["reasoning"] = state.get("rationale", "")
        recommendation.metadata["rca_analysis"] = state.get("rca_analysis", {})
        evidence_quality = (
            recommendation.metadata["rca_analysis"].get("evidence_quality", {})
            if isinstance(recommendation.metadata["rca_analysis"], dict)
            else {}
        )
        available_evidence_count = int(
            (recommendation.metadata["rca_analysis"].get("evidence_validation") or {}).get("available_count") or 0
        )
        accepted_count = int(evidence_quality.get("accepted_evidence") or 0)
        recommendation.metadata["evidence_quality"] = {
            "evidence_coverage": min(1.0, accepted_count / 2.0),
            "citation_coverage": min(1.0, accepted_count / max(1, available_evidence_count)),
            "evidence_fresh": int(evidence_quality.get("fresh_direct_evidence") or 0) > 0,
            "conflict_count": 1 if evidence_quality.get("contradictory") else 0,
            "independent_source_count": int(evidence_quality.get("independent_sources") or 0),
            "direct_observation_count": int(evidence_quality.get("direct_evidence") or 0),
            "sufficiency": str(evidence_quality.get("sufficiency") or "insufficient"),
        }
        recommendation.metadata["impact_analysis"] = state.get("impact_analysis", {})
        recommendation.metadata["remediation_analysis"] = state.get("remediation_analysis", {})
        recommendation.metadata["investigation_report"] = state.get("investigation_report", {})
        recommendation.metadata["hypothesis_analysis"] = state.get("hypothesis_analysis", {})
        remediation_analysis = state.get("remediation_analysis", {})
        recommendation.metadata["execution_plan"] = {
            key: remediation_analysis.get(key)
            for key in (
                "schema_version", "mutating", "preflight_commands", "commands",
                "validation_commands", "rollback_commands", "remediation_target",
                "plan_kind", "execution_ready", "readiness_blocks",
                "evidence_basis", "investigation_report", "ranked_hypotheses",
            )
        }
        recommendation.metadata["detected_errors"] = state.get("gathered_context", {}).get("detected_errors", [])
        recommendation.metadata["detected_error_count"] = len(recommendation.metadata["detected_errors"])
        recommendation.metadata["service"] = str(context.alert.service or "")
        recommendation.metadata["environment"] = str(context.alert.environment or "prod")
        recommendation.metadata["remediation_target"] = str(state.get("remediation_target") or context.alert.service or "")
        recommendation.metadata["recommended_commands"] = state.get("commands", [])
        code_review = state.get("gathered_context", {}).get("code_review", {})
        recommendation.metadata["code_review"] = code_review if isinstance(code_review, dict) else {}
        recommendation.metadata["proposed_code_changes"] = (
            code_review.get("proposed_changes", []) if isinstance(code_review, dict) else []
        )
        if runbook_present:
            runbook_text = str(context.runbook or "").strip()
            service_match = float(str(context.alert.service or "").lower() in runbook_text.lower())
            evidence_coverage = min(1.0, len(accepted_evidence_ids) / 2.0)
            matched_rb = (
                context.metadata.get("matched_learned_runbook")
                if isinstance(context.metadata, dict) and isinstance(context.metadata.get("matched_learned_runbook"), dict)
                else {}
            )
            rb_id = str(matched_rb.get("runbook_id") or "").strip()
            rb_ver = int(matched_rb.get("runbook_version") or 0) if matched_rb else 0
            rb_slug = str(matched_rb.get("runbook_slug") or "").strip()
            if not rb_id and isinstance(context.metadata, dict):
                for rag_hit in (context.metadata.get("rag_matches") or []):
                    if not isinstance(rag_hit, dict):
                        continue
                    path_val = str(rag_hit.get("path") or "").strip()
                    gov_match = re.match(r"^governed://[^/]+/([0-9a-fA-F-]{36})/v(\d+)$", path_val)
                    if gov_match:
                        rb_id = gov_match.group(1)
                        rb_ver = int(gov_match.group(2))
                        break
            recommendation.metadata.update({
                "runbook_id": rb_id or str(uuid5(NAMESPACE_URL, runbook_text)),
                "runbook_version": rb_ver or 1,
                "runbook_status": "approved",
                "runbook_match_score": round((service_match * 0.6) + (evidence_coverage * 0.4), 4),
            })
            if rb_slug:
                recommendation.metadata["runbook_slug"] = rb_slug
        discovery_report = (
            context.metadata.get("discovery_report")
            if isinstance(context.metadata.get("discovery_report"), dict)
            else {}
        )
        discovery_analysis = (
            discovery_report.get("report")
            if isinstance(discovery_report.get("report"), dict)
            else {}
        )
        rca_analysis = state.get("rca_analysis", {}) if isinstance(state.get("rca_analysis"), dict) else {}
        impact_analysis = state.get("impact_analysis", {}) if isinstance(state.get("impact_analysis"), dict) else {}
        recommendation.metadata["external_knowledge_eligible"] = bool(
            discovery_analysis.get("external_knowledge_eligible")
            or rca_analysis.get("external_knowledge_eligible")
            or impact_analysis.get("external_knowledge_eligible")
        )
        recommendation.metadata["external_knowledge_used"] = bool(
            discovery_analysis.get("external_knowledge_used")
            or rca_analysis.get("external_knowledge_used")
            or impact_analysis.get("external_knowledge_used")
        )
        external_tools: list[str] = []
        for tool_list in (
            discovery_analysis.get("external_tools_used"),
            rca_analysis.get("external_tools_used"),
            impact_analysis.get("external_tools_used"),
        ):
            if isinstance(tool_list, list):
                external_tools.extend(str(item) for item in tool_list if str(item or "").strip())
        recommendation.metadata["external_tools_used"] = list(dict.fromkeys(external_tools))
        recommendation.metadata["external_knowledge_error"] = (
            str(discovery_analysis.get("external_knowledge_error") or "")[:300] or None
        )
        fallback_usages = [usage for usage in state.get("model_usage", []) if self._model_call_is_fallback(usage)]
        human_guided = (context.metadata or {}).get("human_guided_input") if isinstance(context.metadata, dict) else {}
        historical_guidance = (
            (context.metadata or {}).get("historical_human_guidance")
            if isinstance(context.metadata, dict) and isinstance((context.metadata or {}).get("historical_human_guidance"), dict)
            else {}
        )
        matched_learned_rb = (
            (context.metadata or {}).get("matched_learned_runbook")
            if isinstance(context.metadata, dict) and isinstance((context.metadata or {}).get("matched_learned_runbook"), dict)
            else {}
        )
        iterative_inv = state.get("gathered_context", {}).get("iterative_investigation") or {}
        has_validated_learned = bool(
            isinstance(iterative_inv, dict)
            and iterative_inv.get("conclusive") is True
            and (
                (isinstance(historical_guidance, dict) and str(historical_guidance.get("root_cause") or historical_guidance.get("observed_symptoms") or "").strip())
                or (isinstance(matched_learned_rb, dict) and str(matched_learned_rb.get("runbook_id") or "").strip())
            )
        )
        has_usable_human = bool(
            (
                isinstance(human_guided, dict)
                and str(human_guided.get("evidence_id") or "").strip()
                and str(human_guided.get("root_cause") or human_guided.get("observed_symptoms") or "").strip()
            )
            or has_validated_learned
        )
        recommendation.metadata["fallback_used"] = bool(fallback_usages) and not has_usable_human
        recommendation.metadata["fallback_reason"] = "; ".join(
            str(usage.get("error") or usage.get("fallback_reason") or "model-router fallback")
            for usage in fallback_usages
        )[:800] or None
        raw_impact_confidence = float(impact_analysis.get("confidence_score") or 0.0)
        recommendation.metadata["quality_gate"] = remediation_quality_gate(
            state.get("remediation_analysis", {}),
            rca_confidence=float(rca_analysis.get("confidence_score") or 0.0),
            impact_confidence=max(0.75, raw_impact_confidence) if has_usable_human else raw_impact_confidence,
            risk=recommendation.risk,
            environment=str(context.alert.environment or "prod"),
            fallback_used=bool(fallback_usages) and not has_usable_human,
            evidence_quality=(
                rca_analysis.get("evidence_quality")
                if isinstance(rca_analysis.get("evidence_quality"), dict)
                else None
            ),
            context_degraded=False if has_usable_human else bool(
                (context.metadata.get("context_graph") or {}).get("degraded")
                if isinstance(context.metadata.get("context_graph"), dict)
                else False
            ),
        )
        citations = [f"incident://{context.incident_id}"]
        if runbook_present:
            citations.append(f"runbook://{context.alert.service}")
        if discovery_evidence:
            citations.append(f"discovery://{context.incident_id}")
            evidence_by_id = {
                str(item.get("evidence_id")): str(item.get("uri") or "")
                for item in discovery_evidence
                if isinstance(item, dict) and str(item.get("evidence_id") or "").strip()
            }
            citations.extend(
                evidence_by_id[evidence_id]
                for evidence_id in accepted_evidence_ids
                if evidence_by_id.get(evidence_id)
            )
        citations.extend(
            str(item)
            for item in rca_analysis.get("external_citations", [])
            if str(item or "").strip()
        )
        citations.extend(
            str(item)
            for item in impact_analysis.get("external_citations", [])
            if str(item or "").strip()
        )
        recommendation.metadata["citations"] = list(dict.fromkeys(citations))
        external_judge = await self._judge_groundedness(
            prediction=f"{recommendation.root_cause} {recommendation.recommended_action} {recommendation.rationale}",
            context_text=context.runbook or "",
        )
        recommendation.metadata["evaluation"] = build_quality_evaluation(
            prediction={
                "root_cause": recommendation.root_cause,
                "impact": recommendation.impact,
                "recommended_action": recommendation.recommended_action,
                "rationale": recommendation.rationale,
                "commands": recommendation.commands,
            },
            context={
                "alert": context.alert.model_dump(mode="json"),
                "runbook": context.runbook,
                "related_incidents": context.related_incidents,
                "metadata": context.metadata,
            },
            confidence=recommendation.confidence,
            citations=recommendation.metadata["citations"],
            rag_matches=context.metadata.get("rag_matches", []) if isinstance(context.metadata, dict) else [],
            runbook_found=runbook_present,
            fallback_used=any(
                str((usage or {}).get("provider") or "").lower() == "fallback"
                or str((usage or {}).get("model") or "").lower() == "fallback"
                or "error" in (usage or {})
                for usage in state.get("model_usage", [])
            ),
            external=external_judge,
        )
        self._publish_evaluation(recommendation=recommendation, report=recommendation.metadata["evaluation"])
        return recommendation

    async def resolve_with_runtime(self, context: Context) -> Recommendation:
        runtime_context = AgentContext.from_context(context)
        runtime_result = await self.runtime.run(self, runtime_context)
        recommendation = runtime_result.result
        if not isinstance(recommendation, Recommendation):
            raise ValidationError("resolution runtime produced non-recommendation output")
        recommendation.metadata["runtime"] = {
            "status": runtime_result.state.execution_status,
            "retry_count": runtime_result.state.retries,
            "reflection": runtime_result.reflection,
        }
        await self.memory_store.append(
            "incident-memory",
            {
                "incident_id": str(context.incident_id),
                "service": context.alert.service,
                "recommended_action": recommendation.recommended_action,
                "confidence": recommendation.confidence,
                "reflection": runtime_result.reflection,
            },
        )
        return recommendation

    async def initialize(self, context: AgentContext, state: Any) -> None:
        state.execution_status = "analyzing"

    async def plan(self, context: AgentContext, state: Any) -> dict[str, Any]:
        payload = context.previous_agent_results.get("context-agent") or context.previous_agent_results.get("context")
        model_task_count = 3
        if not isinstance(payload, dict):
            raise ContextFailure("resolution agent requires serialized context payload")
        return {
            "phase": "resolution",
            "steps": [
                "collect_context", "plan_investigation", "rank_hypotheses", "generate_rca",
                "impact_analysis", "generate_fix", "confidence_scoring",
            ],
            "model_task_count": model_task_count,
        }

    async def execute(self, context: AgentContext) -> Recommendation:
        context_payload = context.previous_agent_results.get("context-agent") or context.previous_agent_results.get("context")
        if not isinstance(context_payload, dict):
            raise ContextFailure("AgentContext.previous_agent_results must include serialized context")
        recommendation = await self.resolve(Context.model_validate(context_payload))
        context.set_result(self.name, recommendation.model_dump(mode="json"))
        return recommendation

    async def validate(self, result: Any) -> bool:
        if not isinstance(result, Recommendation):
            return False
        if result.confidence < 0 or result.confidence > 1:
            raise ValidationError("confidence must be between zero and one")
        evidence_ids = result.metadata.get("evidence_ids", [])
        rca_status = str(result.metadata.get("rca_status") or "").strip().lower()
        if result.confidence == 0 and rca_status != "insufficient_evidence":
            raise ValidationError("zero confidence requires explicit insufficient_evidence status")
        if (
            result.confidence > 0
            and (not isinstance(evidence_ids, list) or not evidence_ids)
            and rca_status != "insufficient_evidence"
        ):
            raise ValidationError("recommendation must include evidence_ids")
        return True

    async def reflect(
        self,
        context: AgentContext,
        state: Any,
        *,
        result: Any | None,
        error: Exception | None,
    ) -> dict[str, Any]:
        confidence = float(result.confidence) if isinstance(result, Recommendation) else 0.0
        quality = "high" if confidence >= 0.85 else "medium" if confidence >= 0.65 else "low"
        return {
            "agent": self.name,
            "quality": quality,
            "lessons_learned": [
                "Preserve runbook and incident evidence links in every recommendation.",
                "Escalate to approval path when confidence is below policy threshold.",
            ],
            "failed_tool_calls": [],
            "missing_evidence": [] if confidence >= 0.5 else ["runbook", "related_incidents"],
            "confidence_adjustment": 0.0,
            "error": str(error) if error else None,
        }

/** Keep recorded observations distinct from explanatory causal claims. */
export function administrativeDuplicateReference(closure: Record<string, unknown>, currentIncident: string): string | null {
  if (closure.closure_kind !== "manual") return null;
  const details = closure.details as Record<string, unknown> | undefined;
  const metadata = details?.metadata as Record<string, unknown> | undefined;
  const comment = typeof metadata?.operator_comment === "string" ? metadata.operator_comment : "";
  if (!/^Administrative duplicate closure:/i.test(comment)) return null;
  const reference = /\bCanonical incident ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/i.exec(comment)?.[1]?.toLowerCase();
  return reference && reference !== currentIncident.toLowerCase() ? reference : null;
}

export function causalPresentation(statement: string, confidence: unknown, hasBoundEvidence = true) {
  const raw = statement.trim();
  const observationOnly = /^(?:Observed signal requiring causal confirmation|Investigation inconclusive):/i.test(raw)
    || /^[{[]/.test(raw) || /["'](?:alert|source|series)["']\s*:/.test(raw);
  const unsupported = Boolean(raw) && !hasBoundEvidence;
  const excluded = observationOnly || unsupported;
  const number = typeof confidence === "number" ? confidence : NaN;
  return {
    statement: excluded ? "No explanatory causal hypothesis recorded" : raw,
    unsupported,
    rawObservation: excluded ? raw : "",
    confidence: !excluded && Number.isFinite(number) && number >= 0 && number <= 1 ? Math.round(number * 100) : null,
    hasCausalStatement: Boolean(raw) && !excluded,
  };
}

export function investigationFindings(rca: Record<string, unknown>) {
  const strings = (value: unknown): string[] => Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && Boolean(item.trim())) : [];
  const alternatives = (Array.isArray(rca.alternative_causes) ? rca.alternative_causes : []).flatMap((item) => {
    if (typeof item === "string" && item.trim()) return [{ cause: item, check: "" }];
    if (!item || typeof item !== "object") return [];
    const value = item as Record<string, unknown>;
    return typeof value.cause === "string" && value.cause.trim()
      ? [{ cause: value.cause, check: typeof value.falsification_check === "string" ? value.falsification_check : "" }] : [];
  });
  return {
    supportingSignals: strings(rca.supporting_signals),
    observations: strings(rca.causal_chain),
    limitations: typeof rca.grounding_notes === "string" ? rca.grounding_notes : "",
    contradictions: [...strings(rca.contradictions), ...strings(rca.conflicting_evidence)],
    alternatives,
  };
}

export function isRcaGrounded(rca: Record<string, unknown>): boolean {
  const resolved = Array.isArray(rca.resolved_evidence_ids) ? rca.resolved_evidence_ids : [];
  const clear = (value: unknown) => Array.isArray(value) && value.length === 0;
  return rca.grounded === true
    && ["grounded", "confirmed", "conclusive"].includes(String(rca.status).toLowerCase())
    && resolved.length > 0
    && Number(rca.traceable_citation_count) === resolved.length
    && clear(rca.unresolved_evidence_ids)
    && clear(rca.missing_evidence)
    && clear(rca.conflicting_evidence);
}

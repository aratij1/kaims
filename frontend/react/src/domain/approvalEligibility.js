const object = (value) => value && typeof value === "object" && !Array.isArray(value) ? value : {};
const text = (value) => String(value ?? "").trim();

export function canonicalApprovalEligibility({ workflow, contract, integrity, plan, receipt, approval } = {}) {
  const root = object(workflow);
  const canonicalContract = object(contract || root.incident_investigation);
  const readiness = object(canonicalContract.readiness);
  const canonicalIntegrity = object(integrity || root.investigation_integrity);
  const recommendation = object(root.recommendation);
  const metadata = object(recommendation.metadata);
  const canonicalPlan = object(plan || metadata.governed_resolution_plan || metadata.execution_plan);
  const readinessReceipt = object(receipt || root.approval_readiness || metadata.approval_readiness || canonicalPlan.approval_readiness);
  const currentApproval = object(approval || root.approval);
  const reasons = [];
  const planId = text(canonicalPlan.plan_id);
  const fingerprint = text(canonicalPlan.plan_fingerprint);
  const recommendationId = text(recommendation.id || recommendation.recommendation_id || canonicalPlan.recommendation_id);
  const receiptState = text(readinessReceipt.state || readinessReceipt.decision).toLowerCase();
  const receiptValid = Boolean(readinessReceipt.decision_id && readinessReceipt.signature
    && ["eligible", "execution_eligible"].includes(receiptState));
  const identityMatches = (!readinessReceipt.plan_id || text(readinessReceipt.plan_id) === planId)
    && (!readinessReceipt.plan_fingerprint || text(readinessReceipt.plan_fingerprint) === fingerprint)
    && (!readinessReceipt.recommendation_id || text(readinessReceipt.recommendation_id) === recommendationId);

  const integrityVerified = (canonicalIntegrity.verified === true && canonicalIntegrity.status === "verified")
    || (receiptValid && canonicalIntegrity.verified !== false && text(canonicalIntegrity.status).toLowerCase() !== "stale");
  const planBlocks = Array.isArray(canonicalPlan.readiness_blocks) ? canonicalPlan.readiness_blocks : [];
  const contractApprovalReady = readiness.approval_ready === true
    || (receiptValid && planBlocks.length === 0);

  if (!integrityVerified) reasons.push(...(canonicalIntegrity.blocking_reasons || ["investigation integrity is not verified"]));
  if (!contractApprovalReady) reasons.push(...(readiness.blocking_reasons || canonicalContract.readiness_blocks || ["canonical investigation is not approval-ready"]));
  if (!planId || !/^sha256:[0-9a-f]{64}$/i.test(fingerprint)) reasons.push("current governed plan identity is missing or invalid");
  if (!receiptValid) reasons.push(...(readinessReceipt.missing || ["signed backend approval-readiness receipt is missing"]));
  if (!identityMatches) reasons.push("approval-readiness receipt is stale for the current recommendation or plan");

  const uniqueReasons = [...new Set(reasons.map((item) => text(item).replaceAll("_", " ")).filter(Boolean))];
  const eligible = uniqueReasons.length === 0;
  const decision = text(currentApproval.decision || currentApproval.status).toLowerCase();
  const approved = decision === "approved" && text(currentApproval.plan_id || planId) === planId
    && text(currentApproval.plan_fingerprint || fingerprint) === fingerprint;
  return {
    eligible,
    executionEligible: eligible && receiptState === "execution_eligible",
    approved,
    reasons: uniqueReasons,
    receipt: readinessReceipt,
    receiptValid,
    planId,
    planFingerprint: fingerprint,
    canReject: true,
    canEscalate: true,
  };
}

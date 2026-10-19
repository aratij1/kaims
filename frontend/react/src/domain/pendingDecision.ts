export function hasPendingDecision(row: { status?: unknown; approval_status?: unknown; execution_mode?: unknown }) {
  const normalize = (value: unknown) => String(value || "").trim().toLowerCase().replaceAll("-", "_").replaceAll(" ", "_");
  if (["closed", "resolved", "recovered", "cancelled", "rejected"].includes(normalize(row.status))) return false;
  return ["awaiting_approval", "pending_approval", "pending", "queued", "draft", "standby", "required"].includes(normalize(row.approval_status))
    || ["awaiting_approval", "pending_approval", "approval_required"].includes(normalize(row.status));
}

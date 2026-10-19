import { isTestApplicationRecord } from "./legacyShellHelpers";

export function visibleManagedApplication(row: string | Record<string, unknown>) {
  const rawName = String(typeof row === "string" ? row : row?.name || row?.application || "").trim();
  const name = rawName.toLowerCase();
  const status = String(typeof row === "string" ? "" : row?.status || "").trim().toLowerCase();
  // The applications API is the onboarding system of record. Failed and
  // deleted registrations must never become selectable workspaces.
  if (["failed", "deleted"].includes(status)) return null;
  if (["kaims", "kaiops", "kaims-core", "kaiops-core"].includes(name)) return typeof row === "string" ? "KaiMS" : { ...row, name: "KaiMS" };
  if (name === "telemetry") return typeof row === "string" ? "Telemetry" : { ...row, name: "Telemetry" };
  // Alert-derived strings are not authoritative application registrations and
  // can contain hundreds of transient service/project identities. Registered
  // application objects are authoritative and belong in the workspace picker.
  if (typeof row === "string" || !rawName) return null;
  // ParaBank is an intentionally onboarded public banking application, not a
  // generated UX fixture, despite "Demo" being part of its product name.
  if (name.includes("parabank")) return { ...row, name: rawName };
  return isTestApplicationRecord(row) ? null : { ...row, name: rawName };
}

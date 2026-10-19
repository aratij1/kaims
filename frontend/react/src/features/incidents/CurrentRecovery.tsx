import {useEffect, useRef, useState} from "react";
import {routeJson} from "../../services/routeApi";
import {formatIstTimestamp} from "../../utils/presentation";
type Data = Record<string, unknown>;

export function currentRecoveryVerified(observation: Data, now = Date.now()) {
  return observation.status === "verified" && Boolean(observation.validation_checksum && observation.observation_id)
    && new Date(String(observation.valid_until || "")).getTime() > now;
}

export function CurrentRecovery({incidentId, accessToken, observation, onObserved}: {
  incidentId: string; accessToken: string; observation: Data; onObserved: (value: Data) => void;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const request = useRef<AbortController>();
  useEffect(() => () => request.current?.abort(), []);
  async function verify() {
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setPending(true); setError("");
    try {
      const result = await routeJson(`/api-gateway/incidents/${encodeURIComponent(incidentId)}/recovery-observation`, {
        method: "POST", headers: {Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json"},
        body: "{}", timeoutMs: 30000, maxAttempts: 1, signal: controller.signal,
      });
      const payload = result as Data;
      const observed = payload.data && typeof payload.data === "object" ? payload.data as Data : payload;
      if (!controller.signal.aborted) onObserved(observed);
    } catch (failure) {
      if (!controller.signal.aborted) setError(String((failure as Error).message));
    } finally { if (!controller.signal.aborted) setPending(false); }
  }
  const checks = Array.isArray(observation.checks) ? observation.checks as Data[] : [];
  return <article className="ic-context-findings" aria-label="Independent current recovery">
    <h4>Independent recovery checks</h4>
    <p>Checks current service health and alert clearance over a stability window. RCA can continue while recovery is measured.</p>
    <button type="button" className="button-secondary" disabled={pending || !accessToken} onClick={() => void verify()}>{pending ? "Checking recovery…" : "Verify current recovery"}</button>
    {error ? <p role="alert">{error}</p> : null}
    {observation.status && observation.status !== "not_observed" ? <p>Observation: {String(observation.status).replaceAll("_", " ")} · {formatIstTimestamp(observation.observed_at)}</p> : null}
    {checks.length ? <ul>{checks.map((check, index) => <li key={index}>{String(check.kind).replaceAll("_", " ")}: {String(check.status).replaceAll("_", " ")}</li>)}</ul> : null}
    <p>This check does not execute remediation or close the incident.</p>
  </article>;
}

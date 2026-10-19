import { useState } from "react";
import { routeJson } from "../../services/routeApi";

export function InvestigationRetry({ alertId, accessToken, disabled = false }: { alertId: string; accessToken?: string; disabled?: boolean }) {
  const [state, setState] = useState({ pending: false, queued: false, error: "" });
  async function retry() {
    setState({ pending: true, queued: false, error: "" });
    try {
      await routeJson(`/api-gateway/analysis/alerts/${encodeURIComponent(alertId)}/regenerate`, {
        method: "POST", maxAttempts: 1,
        headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
        body: JSON.stringify({ mode: "fresh" }),
      });
      setState({ pending: false, queued: true, error: "" });
    } catch (error) {
      setState({ pending: false, queued: false, error: (error as Error).message || "Investigation request failed." });
    }
  }
  return <div className="ic-context-findings">
    <button type="button" className="button-secondary" disabled={disabled || !alertId || state.pending || state.queued} onClick={() => void retry()}>{state.pending ? "Requesting investigation?" : "Rerun investigation"}</button>
    {state.queued ? <p role="status">Fresh investigation requested. The recorded RCA remains visible until a new result is published; this page refreshes automatically.</p> : null}
    {state.error ? <p role="alert">{state.error}</p> : null}
  </div>;
}

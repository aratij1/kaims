import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { OperationalEventSchema, type OperationalEvent } from "../schemas/operationalEvents";

export const OPERATIONAL_UPDATE_EVENT = "kaiops:operational-update";

export type LiveConnectionState = "disabled" | "connecting" | "connected" | "reconnecting" | "paused";

interface Options {
  accessToken: string;
  paused: boolean;
  onEvent?: (event: OperationalEvent) => void;
}

export function useOperationalEvents({ accessToken, paused, onEvent }: Options) {
  const queryClient = useQueryClient();
  const callback = useRef(onEvent);
  const lastEventId = useRef("");
  const seen = useRef(new Set<string>());
  const [state, setState] = useState<LiveConnectionState>("disabled");
  const [lastEventAt, setLastEventAt] = useState("");
  callback.current = onEvent;

  useEffect(() => {
    if (!accessToken) {
      lastEventId.current = "";
      seen.current.clear();
      setState("disabled");
      return undefined;
    }
    if (paused) {
      setState("paused");
      return undefined;
    }

    let cancelled = false;
    let controller: AbortController | undefined;
    let retryTimer: number | undefined;
    let retry = 0;

    const connect = async () => {
      if (cancelled || document.visibilityState === "hidden") return;
      if (retryTimer) window.clearTimeout(retryTimer);
      controller?.abort();
      controller = new AbortController();
      let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
      setState(retry ? "reconnecting" : "connecting");
      try {
        const response = await fetch("/api-gateway/events/operations", {
          headers: {
            Accept: "text/event-stream",
            Authorization: `Bearer ${accessToken}`,
            ...(lastEventId.current ? { "Last-Event-ID": lastEventId.current } : {}),
          },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error(`SSE connection failed (${response.status})`);
        setState("connected");
        retry = 0;
        reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        while (!cancelled) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          // A broken upstream may never terminate a frame. Reconnect instead
          // of retaining an ever-growing string for the lifetime of the tab.
          if (buffer.length > 256 * 1024) throw new Error("Operational event frame exceeds buffer limit");
          const frames = buffer.split("\n\n");
          buffer = frames.pop() ?? "";
          for (const frame of frames) {
            let id = "";
            let type = "message";
            let rawData = "{}";
            for (const line of frame.split("\n")) {
              if (line.startsWith("id:")) id = line.slice(3).trim();
              else if (line.startsWith("event:")) type = line.slice(6).trim();
              else if (line.startsWith("data:")) rawData = line.slice(5).trim();
            }
            if (!id || seen.current.has(id)) continue;
            let data: unknown;
            try { data = JSON.parse(rawData); } catch { continue; }
            const parsed = OperationalEventSchema.safeParse({ id, type, data });
            if (!parsed.success) continue;
            seen.current.add(id);
            if (seen.current.size > 1000) seen.current = new Set([id]);
            lastEventId.current = id;
            const event = parsed.data;
            // Heartbeats prove transport liveness but do not represent a data
            // change. Updating React state for each five-second heartbeat made
            // every route consuming the shared runtime rerender, which appeared
            // as synchronized flicker in Live Alerts and Approvals.
            if (type !== "heartbeat") {
              setLastEventAt(new Date().toISOString());
              // Refresh only the domain changed by this event. Invalidating the
              // broad `api` namespace repainted unrelated mounted workspaces.
              if (type === "alert.created") void queryClient.invalidateQueries({ queryKey: ["alerts"], exact: false });
              else void queryClient.invalidateQueries({ queryKey: [type.split(".", 1)[0]], exact: false });
              window.dispatchEvent(new CustomEvent(OPERATIONAL_UPDATE_EVENT, { detail: { type: event.type } }));
              callback.current?.(event);
            }
          }
        }
      } catch (error) {
        if (cancelled || (error instanceof DOMException && error.name === "AbortError")) return;
      } finally {
        if (reader) {
          try { await reader.cancel(); } catch { /* The request may already be aborted. */ }
          reader.releaseLock();
        }
      }
      if (!cancelled && document.visibilityState === "visible") {
        retry += 1;
        const delay = Math.min(30_000, 1_000 * 2 ** Math.min(retry, 5));
        setState("reconnecting");
        retryTimer = window.setTimeout(connect, delay);
      }
    };

    const onVisibility = () => {
      if (retryTimer) window.clearTimeout(retryTimer);
      if (document.visibilityState === "hidden") {
        controller?.abort();
        setState("paused");
      } else if (!cancelled) {
        retry = 0;
        void connect();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    void connect();
    return () => {
      cancelled = true;
      controller?.abort();
      if (retryTimer) window.clearTimeout(retryTimer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [accessToken, paused, queryClient]);

  return { state, lastEventAt };
}

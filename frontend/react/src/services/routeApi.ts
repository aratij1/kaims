import { queryClient } from "../app/queryClient";
import { parseInternalApiResponse } from "../schemas/apiContracts";

const headerScopes = new Map<string, number>();
let nextHeaderScope = 0;
function requestScope(headers: HeadersInit | undefined): number {
  const identity = JSON.stringify([...new Headers(headers).entries()].sort(([a], [b]) => a.localeCompare(b)));
  let scope = headerScopes.get(identity);
  if (scope === undefined) {
    scope = ++nextHeaderScope;
    headerScopes.set(identity, scope);
    if (headerScopes.size > 64) headerScopes.delete(headerScopes.keys().next().value!);
  }
  return scope;
}

export type RouteRequestOptions = RequestInit & { maxAttempts?: number; timeoutMs?: number; staleTimeMs?: number };

async function requestNetwork<T>(path: string, options: RouteRequestOptions): Promise<T> {
  const method = String(options.method || "GET").toUpperCase();
  const attempts = Math.min(Math.max(Math.floor(options.maxAttempts ?? (["GET", "HEAD"].includes(method) ? 3 : 1)), 1), 4);
  const timeoutMs = options.timeoutMs ?? 15_000;
  const request: RouteRequestOptions = { ...options };
  delete request.maxAttempts;
  delete request.timeoutMs;
  delete request.staleTimeMs;
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    if (options.signal?.aborted) throw options.signal.reason || new DOMException("Request cancelled", "AbortError");
    let retryable = true;
    const controller = new AbortController();
    const forwardAbort = () => controller.abort(options.signal?.reason);
    options.signal?.addEventListener("abort", forwardAbort, { once: true });
    const timeout = globalThis.setTimeout(() => controller.abort(new DOMException("Request timed out", "TimeoutError")), timeoutMs);
    try {
      const headers = new Headers(request.headers);
      if (!headers.has("Accept")) headers.set("Accept", "application/json");
      if (request.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
      const response = await fetch(path, { ...request, cache: "no-store", headers, signal: controller.signal });
      const text = await response.text();
      if (!response.ok) {
        const error = new Error(`HTTP ${response.status}: ${text || "request failed"}`);
        retryable = response.status >= 500 || response.status === 429;
        if (!retryable || attempt === attempts) throw error;
        lastError = error;
      } else {
        retryable = false; // Invalid JSON/contracts are not transport failures.
        const payload = text ? JSON.parse(text) : null;
        return parseInternalApiResponse(path, String(request.method || "GET"), payload) as T;
      }
    } catch (error) {
      lastError = error;
      if (!retryable || options.signal?.aborted || attempt === attempts) throw error;
    } finally {
      globalThis.clearTimeout(timeout);
      options.signal?.removeEventListener("abort", forwardAbort);
    }
    await new Promise((resolve) => globalThis.setTimeout(resolve, attempt * 500));
  }
  throw lastError instanceof Error ? lastError : new Error("Request failed");
}

/** Temporary typed boundary for route-owned adapters during legacy-shell retirement. */
export async function routeJson<T = unknown>(path: string, options: RouteRequestOptions = {}): Promise<T> {
  const method = String(options.method || "GET").toUpperCase();
  if (method !== "GET") {
    const result = await requestNetwork<T>(path, options);
    await queryClient.invalidateQueries({ queryKey: ["route-api"] });
    return result;
  }
  // A caller-owned signal must not be replaced by a shared cache request.
  if (options.signal) return requestNetwork<T>(path, options);
  return queryClient.fetchQuery({
    queryKey: ["route-api", requestScope(options.headers), path],
    retry: false, // requestNetwork owns the bounded retry policy.
    queryFn: ({ signal }) => requestNetwork<T>(path, { ...options, signal }),
    staleTime: options.staleTimeMs ?? 0,
  });
}

import { afterEach, expect, it, vi } from "vitest";
import { routeJson } from "./routeApi";
import { queryClient } from "../app/queryClient";
vi.mock("../schemas/apiContracts", () => ({ parseInternalApiResponse: (_path: string, _method: string, data: unknown) => data }));
afterEach(() => { queryClient.clear(); vi.unstubAllGlobals(); });
it("isolates cached responses by session and tenant headers", async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(new Response('{"owner":"a"}')).mockResolvedValueOnce(new Response('{"owner":"b"}'));
  vi.stubGlobal("fetch", fetcher);
  const a = await routeJson("/api-gateway/example", { headers: { Authorization: "Bearer a" }, staleTimeMs: 60000 });
  const b = await routeJson("/api-gateway/example", { headers: { Authorization: "Bearer b" }, staleTimeMs: 60000 });
  expect(a).toEqual({ owner: "a" });expect(b).toEqual({ owner: "b" });expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls[0][1].cache).toBe("no-store");
  expect(JSON.stringify(queryClient.getQueryCache().getAll().map(q => q.queryKey))).not.toContain("Bearer");
});
it("does not automatically replay a mutation after a server failure", async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response("unavailable", { status: 503 }));vi.stubGlobal("fetch", fetcher);
  await expect(routeJson("/api-gateway/action", { method: "POST" })).rejects.toThrow("503");expect(fetcher).toHaveBeenCalledTimes(1);
});
it("does not retry an unauthorized read through either retry layer", async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response("denied", { status: 403 }));vi.stubGlobal("fetch", fetcher);
  await expect(routeJson("/api-gateway/example")).rejects.toThrow("403");expect(fetcher).toHaveBeenCalledTimes(1);
});
it("does not fetch when the caller already cancelled", async () => {
  const fetcher = vi.fn();vi.stubGlobal("fetch", fetcher);const controller = new AbortController();controller.abort();
  await expect(routeJson("/api-gateway/example", { signal: controller.signal })).rejects.toThrow();expect(fetcher).not.toHaveBeenCalled();
});

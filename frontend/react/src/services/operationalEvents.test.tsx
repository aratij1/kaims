// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { useOperationalEvents } from "./operationalEvents";

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>;
}

afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it("releases an oversized unterminated event stream instead of retaining it", async () => {
  vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
  const stream = new ReadableStream<Uint8Array>({
    start(controller) { controller.enqueue(new TextEncoder().encode("x".repeat(256 * 1024 + 1))); },
  });
  const fetch = vi.fn().mockResolvedValue({ ok: true, body: stream });
  vi.stubGlobal("fetch", fetch);
  const hook = renderHook(() => useOperationalEvents({ accessToken: "token", paused: false }), { wrapper });
  await waitFor(() => expect(hook.result.current.state).toBe("reconnecting"));
  expect(stream.locked).toBe(false);
  expect(fetch).toHaveBeenCalledTimes(1);
});

it("cancels a pending reconnect before reconnecting on tab visibility", async () => {
  vi.useFakeTimers();
  let visibility: DocumentVisibilityState = "visible";
  vi.spyOn(document, "visibilityState", "get").mockImplementation(() => visibility);
  const fetch = vi.fn().mockRejectedValueOnce(new Error("offline"))
    .mockImplementation(() => new Promise(() => {}));
  vi.stubGlobal("fetch", fetch);
  renderHook(() => useOperationalEvents({ accessToken: "token", paused: false }), { wrapper });
  await act(async () => { await Promise.resolve(); });
  await act(async () => {
    visibility = "hidden"; document.dispatchEvent(new Event("visibilitychange"));
    visibility = "visible"; document.dispatchEvent(new Event("visibilitychange"));
    await Promise.resolve();
  });
  expect(fetch).toHaveBeenCalledTimes(2);
  await act(async () => { await vi.advanceTimersByTimeAsync(2500); });
  expect(fetch).toHaveBeenCalledTimes(2);
});

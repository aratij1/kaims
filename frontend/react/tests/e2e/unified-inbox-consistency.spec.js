import { expect, test } from "@playwright/test";

test("one inbox feed owns filters, cursor, errors, and browser navigation", async ({ page }) => {
  test.setTimeout(120000);
  const errors = [];
  const legacyCursors = [];
  const requests = [];
  let fail = false;
  page.on("pageerror", error => errors.push(error.message));
  await page.route("**/api-gateway/**", async route => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api-gateway/, "");
    if (path === "/incidents/inbox/feed") {
      requests.push(url.search);
      if (fail) return route.fulfill({ status: 503, json: { detail: "Inbox temporarily unavailable" } });
      const second = url.searchParams.get("cursor") === "unified-next";
      const filtered = url.searchParams.get("inbox_view") === "needs_me";
      const count = second || filtered ? 1 : 10;
      const rows = Array.from({ length: count }, (_, index) => ({ record_type: "incident", score: 100,
        row: { id: `00000000-0000-4000-8000-${String((second ? 11 : 1) + index).padStart(12, "0")}`,
          incident_id: `00000000-0000-4000-8000-${String((second ? 11 : 1) + index).padStart(12, "0")}`,
          title: `Contract incident ${(second ? 11 : 1) + index}`, service: "api-gateway", severity: "high",
          status: filtered ? "waiting_for_human" : "investigating", updated_at: "2026-09-13T10:00:00Z" } }));
      return route.fulfill({ json: { data: { rows, filtered_count: filtered ? 1 : 11, total_count: 11,
        record_counts: { incidents: 11, alerts: 0 }, view_counts: { all: 11, needs_me: 1, kai_handling: 10 },
        previous_cursor: second ? "unified-previous" : null,
        next_cursor: second || filtered ? null : "unified-next" } } });
    }
    if (path.startsWith("/incidents") && url.searchParams.has("cursor")) legacyCursors.push(url.search);
    const body = path === "/auth/config" ? { mode: "local", local_development_only: true }
      : ["/auth/login", "/auth/refresh"].includes(path) ? { access_token: "fixture-token", refresh_token: "fixture-refresh", user: { id: 1, username: "admin", role_name: "Administrator" } }
      : path === "/applications" ? { data: { rows: [{ id: "kaims", name: "KaiMS", status: "active" }] } }
      : path === "/healthz" ? { status: "ok" } : { data: { rows: [] }, rows: [] };
    return route.fulfill({ json: body });
  });
  await page.goto("/incidents");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("fixture-password");
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: "Unified Inbox" })).toBeVisible();
  await page.getByLabel("Inbox records").selectOption("incidents");
  await expect(page.getByText("Showing 1-10 of 11")).toBeVisible();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await expect(page.getByText("Showing 11-11 of 11")).toBeVisible();
  expect(new URL(page.url()).searchParams.get("page")).toBe("2");
  await page.reload();
  if (await page.getByLabel("Username").isVisible()) {
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("fixture-password");
    await page.getByRole("button", { name: /sign in/i }).click();
  }
  await expect(page.getByText("Showing 11-11 of 11")).toBeVisible();
  await page.getByRole("button", { name: "Previous", exact: true }).click();
  await expect(page.getByText("Showing 1-10 of 11")).toBeVisible();
  await page.getByRole("button", { name: /^Needs me/ }).click();
  await expect(page.getByText("Showing 1-1 of 1")).toBeVisible();
  await expect(page.getByRole("button", { name: "Next", exact: true })).toBeDisabled();
  fail = true;
  await page.getByRole("button", { name: "Refresh queue", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: /Showing the last successfully loaded page/ })).toHaveCount(1);
  await expect(page.getByText("Contract incident 1", { exact: true })).toBeVisible();
  fail = false;
  await page.getByRole("button", { name: "Refresh queue", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: /Showing the last successfully loaded page/ })).toHaveCount(0);
  expect(requests.some(query => query.includes("unified-next"))).toBe(true);
  expect(legacyCursors).toEqual([]);
  expect(errors).toEqual([]);
});

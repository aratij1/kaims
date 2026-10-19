import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.route("**/api-gateway/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api-gateway/, "");
    const body = path === "/auth/config"
      ? { mode: "local", local_development_only: true }
      : path === "/auth/login"
        ? { access_token: "admin-token", refresh_token: "refresh-token", user: { id: 1, username: "admin", role_name: "Administrator" } }
        : path === "/healthz"
          ? { status: "ok", service: "api-gateway" }
          : path.startsWith("/alerts/all") || path.startsWith("/landing-pad/recent")
            ? { data: { rows: [] } }
            : { data: [], rows: [], summary: {}, items: [] };
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
});

async function signInToAiHub(page) {
  await page.goto("/knowledge");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("Admin@123456");
  await page.getByRole("button", { name: "Sign In" }).click();
  await expect(page).toHaveURL(/\/knowledge$/);
}

test("AI Hub presents health, capabilities, and accessible section navigation", async ({ page }) => {
  await signInToAiHub(page);
  await expect(page.getByRole("heading", { level: 2, name: "Operational Knowledge", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { level: 3, name: "Operational intelligence" })).toBeVisible();
  await expect(page.getByRole("region", { name: "AI platform health" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "From evidence to governed action" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("button", { name: /Agent observability/ }).click();
  await expect(page.getByRole("tab", { name: "Agent activity" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("heading", { name: "Observed agent activity" })).toBeVisible();
  await page.getByRole("tab", { name: "Knowledge development" }).click();
  await expect(page.getByRole("heading", { name: "Resolution learning lifecycle" })).toBeVisible();
  await page.getByRole("tab", { name: "Pipeline queues" }).click();
  await expect(page.getByRole("heading", { name: "Pipeline Queue Manager" })).toBeVisible();
  await page.getByRole("tab", { name: "Topology", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Advanced message topology" })).toBeVisible();
});

test("AI Hub overview shows real AI provider health data", async ({ page }) => {
  await page.route("**/api-gateway/model/providers/status", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        data: {
          selected: {}, prompt_cache: {},
          providers: {
            "azure-openai": { configured: true, healthy: true, circuit_open: false, failure_count: 0, model: "gpt-4o" },
            "claude": { configured: false, healthy: true, circuit_open: false, failure_count: 0, model: "claude-sonnet-4-6", reason: "ANTHROPIC_API_KEY is not configured" },
          },
        },
      }),
    });
  });
  await signInToAiHub(page);
  await expect(page.getByRole("heading", { name: "AI provider health" })).toBeVisible();
  const row = page.getByRole("row", { name: /azure-openai/ });
  await expect(row).toContainText("gpt-4o");
  await expect(row).toContainText("Configured");
  await expect(row).toContainText("Healthy");
  const claudeRow = page.getByRole("row", { name: /claude/ });
  await expect(claudeRow).toContainText("Not configured");
});

test("AI Hub overview provider health shows empty state when nothing is returned", async ({ page }) => {
  await signInToAiHub(page);
  await expect(page.getByRole("heading", { name: "AI provider health" })).toBeVisible();
  await expect(page.getByText("No provider status was returned.")).toBeVisible();
});

test("AI Hub overview reflows without horizontal page overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await signInToAiHub(page);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await expect(page.getByRole("button", { name: "Refresh status" })).toBeVisible();
});

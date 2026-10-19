// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { routeJson } from "../../services/routeApi";
import { InvestigationRetry } from "./InvestigationRetry";
vi.mock("../../services/routeApi", () => ({ routeJson: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });
it("requests fresh analysis once and retains a pending result message", async () => {
  vi.mocked(routeJson).mockResolvedValue({ status: "accepted" });
  render(<InvestigationRetry alertId="alert-a" accessToken="test" />);
  fireEvent.click(screen.getByRole("button"));
  await screen.findByRole("status");
  expect(vi.mocked(routeJson).mock.calls[0]).toEqual(["/api-gateway/analysis/alerts/alert-a/regenerate", expect.objectContaining({ method: "POST", maxAttempts: 1, body: JSON.stringify({ mode: "fresh" }) })]);
  expect((screen.getByRole("button") as HTMLButtonElement).disabled).toBe(true);
});
it("shows request failure and permits retry", async () => {
  vi.mocked(routeJson).mockRejectedValue(new Error("Service unavailable"));
  render(<InvestigationRetry alertId="alert-a" />);fireEvent.click(screen.getByRole("button"));
  await screen.findByText("Service unavailable");
  expect((screen.getByRole("button") as HTMLButtonElement).disabled).toBe(false);
});
it("does not submit without a bound alert", () => {
  render(<InvestigationRetry alertId="" />);fireEvent.click(screen.getByRole("button"));
  expect(routeJson).not.toHaveBeenCalled();
});

import { describe, expect, it } from "vitest";
import { availableApplication } from "./applicationSelection";

describe("authoritative application selection", () => {
  const options = ["CheckAPI", "KaiMS", "Telemetry"];
  it("preserves Telemetry even when CheckAPI is first", () => {
    expect(availableApplication("Telemetry", options)).toBe("Telemetry");
  });
  it("canonicalizes saved names without switching applications", () => {
    expect(availableApplication(" telemetry ", options)).toBe("Telemetry");
  });
  it("uses KaiMS for a genuinely unavailable selection", () => {
    expect(availableApplication("removed-project", options)).toBe("KaiMS");
  });
  it("respects an explicitly selected CheckAPI", () => {
    expect(availableApplication("CheckAPI", options)).toBe("CheckAPI");
  });
  it("does not invent an application absent from an authoritative list", () => {
    expect(availableApplication("removed", ["Telemetry"])).toBe("Telemetry");
    expect(availableApplication("Telemetry", [])).toBe("");
  });
});

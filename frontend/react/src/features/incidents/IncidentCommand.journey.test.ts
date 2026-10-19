import { describe, expect, it } from "vitest";
import { collectionDisplayStatus, journeyIndexForStatus } from "./IncidentCommand";

describe("canonical journey stages", () => {
  it("distinguishes queued and retrying evidence from running collection", () => {
    expect(collectionDisplayStatus("collecting", "queued")).toBe("queued_for_evidence");
    expect(collectionDisplayStatus("collecting", "retry_wait")).toBe("waiting_to_retry_evidence");
    expect(collectionDisplayStatus("collecting", "collecting")).toBe("collecting");
    expect(collectionDisplayStatus("closed", "queued")).toBe("closed");
  });
  it.each(["context_ready", "requirements_identified", "collecting", "waiting_for_human", "investigating"])("keeps %s in evidence work rather than detection", status => {
    expect(journeyIndexForStatus(status)).toBe(1);
  });
  it("shows a ready RCA at root cause without pretending resolution has executed", () => {
    expect(journeyIndexForStatus("RCA_READY")).toBe(2);
    expect(journeyIndexForStatus("detected")).toBe(0);
    expect(journeyIndexForStatus("awaiting_approval")).toBe(3);
  });
});

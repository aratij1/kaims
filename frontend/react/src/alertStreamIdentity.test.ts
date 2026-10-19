import { expect, it } from "vitest";
import { mapLandingPadRowToAlertStreamRow } from "./appHelpers";
it("keeps canonical alert identity when an incident relationship is present", () => {
 const row = mapLandingPadRowToAlertStreamRow({ id: "alert-1", incident_id: "incident-2" });
 expect(row.id).toBe("alert-1"); expect(row.alert_id).toBe("alert-1"); expect(row.incident_id).toBe("incident-2");
});
it("prefers explicit canonical alert identity over a landing object identifier", () => {
 const row = mapLandingPadRowToAlertStreamRow({ id: "landing-object", alert_id: "alert-1", incident_id: "incident-2" });
 expect(row.id).toBe("alert-1"); expect(row.alert_id).toBe("alert-1");
});

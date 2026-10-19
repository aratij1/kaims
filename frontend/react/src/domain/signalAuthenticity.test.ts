import {expect,it} from "vitest";
import {isSyntheticSignal,isDemoSignal,isNonProductionSignal} from "./signalAuthenticity";
it("recognizes explicit test markers and configured fault targets", () => {
  expect(isSyntheticSignal({labels:{synthetic:"true"}})).toBe(true);
  expect(isSyntheticSignal({source_alert:{labels:{event_mode:"simulation"}}})).toBe(true);
  expect(isSyntheticSignal({service:"kaiops-fault-lab-service"})).toBe(true);
  expect(isSyntheticSignal({title:"ServiceDown-E2E-20261015090505"})).toBe(true);
});
it("separates observed demo failures from synthetic signals and production", () => {
  const demo = {source:"robot-shop", labels:{event_authenticity:"internal-observed"}};
  expect(isDemoSignal(demo)).toBe(true);
  expect(isSyntheticSignal(demo)).toBe(false);
  expect(isNonProductionSignal(demo)).toBe(true);
  expect(isDemoSignal({name:"DiskSpaceLow",service:"node-exporter"})).toBe(false);
  expect(isDemoSignal({source:"telemetry",name:"RealCustomerOutage",labels:{job:"payments"}})).toBe(false);
  expect(isDemoSignal({labels:{instance:"http://ob-frontend:8080/_healthz"}})).toBe(true);
});
it("does not classify ordinary service names or unknown provenance as fake", () => {
  expect(isSyntheticSignal({service:"payment-test",labels:{synthetic:"false"}})).toBe(false);
  expect(isSyntheticSignal({service:"api-gateway"})).toBe(false);
});

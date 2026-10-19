import { expect, it } from "vitest";
import { causalPresentation, investigationFindings, isRcaGrounded } from "./incidentTruth";
it("does not turn an observed signal or raw JSON into a causal claim", () => {
  for (const input of ['Observed signal requiring causal confirmation: {"alert":5}', '{"source":"prometheus"}', "Observed signal requiring causal confirmation: probe failed"]) {
    expect(causalPresentation(input, 0.69)).toMatchObject({hasCausalStatement:false, confidence:null, rawObservation:input});
  }
});
it("requires a claim-bound valid confidence value", () => {
  expect(causalPresentation("Pool exhausted after connection leak", undefined).confidence).toBeNull();
  expect(causalPresentation("Pool exhausted", null).confidence).toBeNull();
  expect(causalPresentation("Pool exhausted", 0.69)).toMatchObject({hasCausalStatement:true, confidence:69});
  expect(causalPresentation("Pool exhausted", 69).confidence).toBeNull();
});

it("does not present an uncited generic candidate as an evidenced explanation", () => {
  expect(causalPresentation("A recent code or configuration change affected httpbin-failure-lab.", 0.0352, false))
    .toMatchObject({hasCausalStatement:false, confidence:null, unsupported:true});
  expect(causalPresentation("Pool exhausted after connection leak", 0.69, true))
    .toMatchObject({hasCausalStatement:true, confidence:69, unsupported:false});
});

it("does not turn an inconclusive status sentence into a causal hypothesis", () => {
 expect(causalPresentation("Investigation inconclusive: the leading signal is a symptom summary, not a causal mechanism.", 0.4, true))
   .toMatchObject({hasCausalStatement:false, confidence:null});
});

it("retains recorded findings and alternative checks for an inconclusive RCA", () => {
  const rca = { hypothesis: "Investigation inconclusive: no mechanism established.", supporting_signals: ["Proxy exited"], causal_chain: ["Probe failed"], grounding_notes: "Exit code does not establish cause.", contradictions: [], alternative_causes: [{ cause: "Resource pressure", falsification_check: "Inspect memory history." }] };
  expect(investigationFindings(rca)).toEqual({ supportingSignals: ["Proxy exited"], observations: ["Probe failed"], limitations: "Exit code does not establish cause.", contradictions: [], alternatives: [{cause: "Resource pressure", check: "Inspect memory history."}] });
  expect(causalPresentation(rca.hypothesis, .93, true).hasCausalStatement).toBe(false);
});

it("does not invent findings or render malformed values as text", () => {
  expect(investigationFindings({ supporting_signals: [null, {}], causal_chain: "wrong shape", alternative_causes: [null, {}, "Traffic shift"] }))
    .toEqual({supportingSignals: [], observations: [], limitations: "", contradictions: [], alternatives: [{cause: "Traffic shift", check: ""}]});
});

it("requires the full RCA gate rather than an individual grounded claim", () => {
  const rca = {status: "grounded", grounded: true, resolved_evidence_ids: ["E1", "E2"], traceable_citation_count: 2, unresolved_evidence_ids: [], missing_evidence: [], conflicting_evidence: []};
  expect(isRcaGrounded(rca)).toBe(true);
  expect(isRcaGrounded({...rca, grounded: false})).toBe(false);
  expect(isRcaGrounded({...rca, missing_evidence: ["Failure mechanism unconfirmed"]})).toBe(false);
  expect(isRcaGrounded({...rca, unresolved_evidence_ids: ["E3"]})).toBe(false);
  expect(isRcaGrounded({...rca, traceable_citation_count: 1})).toBe(false);
  expect(isRcaGrounded({...rca, conflicting_evidence: ["Contradictory observation"]})).toBe(false);
  expect(isRcaGrounded({status: "grounded", confidence: .99})).toBe(false);
});

it("only links explicit duplicate references from administrative closure notes", async () => {
 const {administrativeDuplicateReference: reference} = await import("./incidentTruth");
 const id = "abc2a6b3-9cc1-40c3-a4e5-fb1a1755f7ac";
 const closure = {closure_kind: "manual", details: {metadata: {operator_comment: `Administrative duplicate closure: Canonical incident ${id} records recovery.`}}};
 expect(reference(closure, "other")).toBe(id);
 expect(reference(closure, id)).toBeNull();
 expect(reference({...closure, closure_kind: "verified_recovery"}, "other")).toBeNull();
 expect(reference({closure_kind: "manual", details: {metadata: {operator_comment: `See ${id}`}}}, "other")).toBeNull();
});

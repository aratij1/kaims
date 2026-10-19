// @vitest-environment jsdom
import {cleanup,render,screen} from "@testing-library/react";
import {afterEach,expect,it} from "vitest";
import {currentRecoveryVerified,CurrentRecovery} from "./CurrentRecovery";
import {RcaSequenceReport} from "./RcaSequenceReport";
afterEach(cleanup);
it("requires a fresh proof identity and checksum",()=>{
 const now=Date.now();const proof={status:"verified",observation_id:"receipt",validation_checksum:"sha256:x",valid_until:new Date(now+60000).toISOString()};
 expect(currentRecoveryVerified(proof,now)).toBe(true);
 expect(currentRecoveryVerified(proof,now+60001)).toBe(false);
 expect(currentRecoveryVerified({...proof,validation_checksum:null},now)).toBe(false);
});
it("shows independently verified health while RCA and execution remain unconfirmed",()=>{
 render(<RcaSequenceReport rca={{status:"insufficient_evidence"}} resolution={{}} execution={{status:"not_started"}} validation={{}} confirmed={false}
  observation={{status:"verified",observation_id:"receipt",validation_checksum:"sha256:x",valid_until:new Date(Date.now()+60000).toISOString()}} />);
 expect(screen.getByText(/Current health independently verified/)).toBeTruthy();
 expect(screen.getByText(/Recorded execution: not_started/)).toBeTruthy();
 expect(screen.getByText(/causal sequence has not been established/)).toBeTruthy();
});
it("exposes failed checks and does not imply remediation or closure",()=>{
 render(<CurrentRecovery incidentId="incident" accessToken="token" observation={{status:"blocked",checks:[{kind:"latency",status:"failed"}]}} onObserved={()=>{}} />);
 expect(screen.getByText("latency: failed")).toBeTruthy();
 expect(screen.getByText(/does not execute remediation or close/)).toBeTruthy();
});

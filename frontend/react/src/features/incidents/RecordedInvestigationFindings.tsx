import type { investigationFindings } from "./incidentTruth";
type Findings = ReturnType<typeof investigationFindings>;

export function RecordedInvestigationFindings({ findings }: { findings: Findings }) {
  return <>{findings.observations.length || findings.limitations ? <article className="ic-context-findings">
              <h4>Recorded investigation findings</h4>
              <p>These are diagnostic observations from this RCA version. They do not establish the cause or customer impact.</p>
              {findings.observations.length ? <ul>{findings.observations.map((observation, index) => <li key={index}>{observation}</li>)}</ul> : null}
              {findings.limitations ? <p><strong>Analysis limitations:</strong> {findings.limitations}</p> : null}
            </article> : null}</>;
}

export function InvestigationAlternatives({ findings }: { findings: Findings }) {
  return <>{findings.alternatives.length ? <article className="ic-context-findings">
              <h4>Alternative explanations to investigate</h4>
              <ul>{findings.alternatives.map((alternative, index) => <li key={index}><p>{alternative.cause}</p>{alternative.check ? <p><strong>Check next:</strong> {alternative.check}</p> : null}</li>)}</ul>
            </article> : null}</>;
}

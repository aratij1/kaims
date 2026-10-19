import { CheckCircle2, CircleAlert } from "lucide-react";
import { formatIstTimestamp, parseUtcTimestamp } from "../../utils/presentation";

type Observation = Record<string, unknown>;
const label = (value: unknown) => value === undefined || value === null || value === "" ? "Not recorded" : String(value);
export function groupRecoveryObservations(observations: Observation[]) {
  const groups = new Map<string, Observation[]>();
  observations.forEach(item => {
    const key = String(item.validator_id || item.kind || "Unidentified validator");
    groups.set(key, [...(groups.get(key) || []), item]);
  });
  return [...groups].map(([id, samples]) => {
    samples.sort((left, right) => (parseUtcTimestamp(left.observed_at)?.getTime() || 0) - (parseUtcTimestamp(right.observed_at)?.getTime() || 0));
    return {id, samples, latest: samples[samples.length - 1], passed: samples.every(sample => sample.passed === true)};
  });
}
export default function RecoveryEvidence({observations}: {observations: Observation[]}) {
  const groups = groupRecoveryObservations(observations);
  if (!groups.length) return <p className="ic-unavailable">No immutable post-state observations were published.</p>;
  return <section className="recovery-evidence" aria-label="Independent recovery observations">
    <header><h4>Independent checks</h4><span>{groups.length} recorded checks / {observations.length} samples</span></header>
    <div className="ic-recovery-checks">{groups.map(group => <article key={group.id}>
      <div className={`recovery-evidence-heading ${group.passed ? "is-passed" : "needs-review"}`}>{group.passed ? <CheckCircle2 size={19} aria-hidden="true" /> : <CircleAlert size={19} aria-hidden="true" />}<strong>{label(group.latest.kind).replaceAll("_", " ")}</strong><span>{group.passed ? "Passed" : "Review samples"}</span></div>
      <dl><div><dt>Latest value</dt><dd>{label(group.latest.measured_value)}</dd></div><div><dt>Expected</dt><dd>{label(group.latest.expected_value)}</dd></div><div><dt>Samples</dt><dd>{group.samples.length}</dd></div></dl>
      <small>Target: {label(group.latest.target_resource_id)}</small>
      <small>Observer: {label(group.latest.connector_id)}</small>
      <small>Last observed: {formatIstTimestamp(group.latest.observed_at)}</small>
      <details><summary>Inspect samples & provenance</summary><div className="recovery-sample-table"><table><thead><tr><th>Observed at</th><th>Value</th><th>Result</th></tr></thead><tbody>{group.samples.map((sample, index) => <tr key={index}><td>{formatIstTimestamp(sample.observed_at)}</td><td>{label(sample.measured_value)}</td><td>{sample.passed === true ? "Passed" : sample.passed === false ? "Failed" : "Unknown"}</td></tr>)}</tbody></table></div><p className="recovery-evidence-id">Validator: {group.id}<br />Result checksum: {label(group.latest.result_checksum)}</p></details>
    </article>)}</div>
  </section>;
}

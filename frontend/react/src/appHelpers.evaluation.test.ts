import { describe, expect, it } from 'vitest';
import { normalizeEvaluationEnvelope, formatQualityPercent } from './appHelpers.jsx';
describe('recorded evaluation metrics', () => {
 it('does not invent quality or hallucination scores when evaluation is absent', () => {
  const report=normalizeEvaluationEnvelope({}, {confidence:0, citationCoverage:0, evidenceCoverage:0});
  expect(report.available).toBe(false);
  expect(report.overallScore).toBeNull();expect(report.hallucinationRisk).toBeNull();
  expect(report.provider).toBe('unavailable');expect(report.requiresReview).toBe(true);
  expect(formatQualityPercent(report.overallScore)).toBe('Unavailable');
 });
 it('preserves measured zero and distinguishes partial reports', () => {
  const report=normalizeEvaluationEnvelope({overall_score:0, hallucination_risk:1,provider:'recorded'});
  expect(report.available).toBe(true);expect(formatQualityPercent(report.overallScore)).toBe('0%');
  expect(formatQualityPercent(report.hallucinationRisk)).toBe('100%');expect(report.groundingScore).toBeNull();
 });
 it('accepts recorded camel-case fields and recommendation confidence', () => {
  expect(normalizeEvaluationEnvelope({groundingScore:.8}).groundingScore).toBe(.8);
  expect(normalizeEvaluationEnvelope({}, {confidence:.7}).confidenceScore).toBe(.7);
  expect(formatQualityPercent(undefined)).toBe('Unavailable');
 });
});

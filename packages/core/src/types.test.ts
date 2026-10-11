import { describe, it, expect } from 'vitest';
import type { Evidence, Report, VerificationStatus, Verdict } from './types.js';
import { PACKAGEGUARD_VERSION, createEmptyEvidence } from './index.js';

describe('Core Types and Helpers', () => {
  it('should have PACKAGEGUARD_VERSION defined', () => {
    expect(PACKAGEGUARD_VERSION).toBe('0.1.0');
  });

  it('should create empty evidence with createEmptyEvidence', () => {
    const ev = createEmptyEvidence('e1', 'test');
    expect(ev.id).toBe('e1');
    expect(ev.scanner).toBe('test');
    expect(ev.severity).toBe('INFO');
    expect(ev.dedupKey).toBe('test:e1');
  });

  it('should construct valid Evidence object', () => {
    const ev: Evidence = {
      id: 'ev-1',
      scanner: 'MetadataScanner',
      category: 'metadata',
      severity: 'LOW',
      confidence: 0.8,
      description: 'Package age < 30 days',
      dedupKey: 'metadata:age:young',
    };
    expect(ev.severity).toBe('LOW');
    expect(ev.confidence).toBe(0.8);
  });

  it('should enforce Report structure and VerificationStatus / Verdict values', () => {
    const status: VerificationStatus = 'PartiallyVerified';
    const verdict: Verdict = 'Review';
    const report: Report = {
      package: 'test-pkg',
      version: '1.0.0',
      riskScore: 85,
      verdict,
      verificationStatus: status,
      breakdown: [],
      hardBlocks: [],
      evidence: [],
      remediation: [],
    };
    expect(report.verdict).toBe('Review');
    expect(report.verificationStatus).toBe('PartiallyVerified');
    expect(report.riskScore).toBe(85);
  });
});

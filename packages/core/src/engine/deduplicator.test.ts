import { describe, it, expect } from 'vitest';
import { deduplicateEvidence } from './deduplicator.js';
import type { Evidence } from '../types.js';

describe('Evidence Deduplicator', () => {
  it('deduplicates evidence by dedupKey keeping all scanner sources attached', () => {
    const ev1: Evidence = {
      id: 'meta-script',
      scanner: 'MetadataScanner',
      category: 'metadata',
      severity: 'MEDIUM',
      confidence: 0.9,
      description: 'postinstall script in package.json',
      dedupKey: 'lifecycle:script:postinstall',
    };

    const ev2: Evidence = {
      id: 'diff-script',
      scanner: 'VersionDiffScanner',
      category: 'version-diff',
      severity: 'HIGH',
      confidence: 0.95,
      description: 'postinstall script added in 1.0.1, absent in previous version',
      dedupKey: 'lifecycle:script:postinstall',
    };

    const ev3: Evidence = {
      id: 'static-script',
      scanner: 'StaticAnalyzer',
      category: 'static-analysis',
      severity: 'CRITICAL',
      confidence: 0.98,
      description: 'Dangerous command in postinstall script',
      dedupKey: 'lifecycle:script:postinstall',
      location: { file: 'package.json:scripts', line: 1 },
      snippet: 'node setup.js',
    };

    const result = deduplicateEvidence([ev1, ev2, ev3]);
    expect(result.length).toBe(1);

    const merged = result[0];
    expect(merged.dedupKey).toBe('lifecycle:script:postinstall');
    expect(merged.severity).toBe('CRITICAL');
    expect(merged.confidence).toBe(0.98);
    expect(merged.sources).toEqual(['MetadataScanner', 'VersionDiffScanner', 'StaticAnalyzer']);
    expect(merged.location).toEqual({ file: 'package.json:scripts', line: 1 });
    expect(merged.snippet).toBe('node setup.js');
  });

  it('preserves distinct evidence items unchanged', () => {
    const ev1: Evidence = {
      id: 'e1',
      scanner: 'MetadataScanner',
      category: 'metadata',
      severity: 'LOW',
      confidence: 0.8,
      description: 'Missing repo',
      dedupKey: 'metadata:repo:missing',
    };

    const ev2: Evidence = {
      id: 'e2',
      scanner: 'VulnScanner',
      category: 'vulnerability',
      severity: 'HIGH',
      confidence: 0.9,
      description: 'CVE-1234',
      dedupKey: 'vuln:target:CVE-1234',
    };

    const result = deduplicateEvidence([ev1, ev2]);
    expect(result.length).toBe(2);
    expect(result[0].sources).toEqual(['MetadataScanner']);
    expect(result[1].sources).toEqual(['VulnScanner']);
  });
});

import { describe, it, expect } from 'vitest';
import { RiskEngine } from './risk-engine.js';
import { renderTerminalReport, renderJsonReport } from '../renderers/report-renderer.js';
import type { Evidence, VerificationStatus } from '../types.js';

describe('RiskEngine and Report Renderers', () => {
  const engine = new RiskEngine();

  it('marks Safe when score >= 80, verificationStatus != Unverified, and no hard blocks', () => {
    const evidence: Evidence[] = [
      {
        id: 'ev-low',
        scanner: 'MetadataScanner',
        category: 'metadata',
        severity: 'LOW',
        confidence: 0.8,
        description: 'Single maintainer',
        dedupKey: 'meta:maint:1',
      },
    ];

    const report = engine.evaluate('safe-pkg', '1.0.0', evidence, 'PartiallyVerified');
    expect(report.verdict).toBe('Safe');
    expect(report.riskScore).toBe(97); // 100 - (4 * 0.8 => 3 pts)
    expect(report.hardBlocks.length).toBe(0);
  });

  it('marks Review when score is below 80 but no hard blocks', () => {
    const evidence: Evidence[] = [
      {
        id: 'ev-med',
        scanner: 'StaticAnalyzer',
        category: 'static-analysis',
        severity: 'MEDIUM',
        confidence: 0.9,
        description: 'Multiple suspicious signals',
        dedupKey: 'static:multi',
      },
      {
        id: 'ev-high',
        scanner: 'MetadataScanner',
        category: 'metadata',
        severity: 'HIGH',
        confidence: 0.9,
        description: 'Suspicious metadata',
        dedupKey: 'meta:sus',
      },
      {
        id: 'ev-diff',
        scanner: 'VersionDiffScanner',
        category: 'version-diff',
        severity: 'HIGH',
        confidence: 0.9,
        description: 'Modified script',
        dedupKey: 'diff:mod',
      },
    ];

    const report = engine.evaluate('review-pkg', '1.0.0', evidence, 'PartiallyVerified');
    expect(report.verdict).toBe('Review');
    expect(report.riskScore).toBeLessThan(80);
    expect(report.hardBlocks.length).toBe(0);
  });

  it('marks Block when score is 95 but integrity failed => Block, not Safe', () => {
    const evidence: Evidence[] = [
      {
        id: 'ev-integrity-fail',
        scanner: 'IntegrityScanner',
        category: 'integrity',
        severity: 'CRITICAL',
        confidence: 1.0,
        description: 'Tarball SHA-512 integrity mismatch',
        dedupKey: 'integrity:mismatch:tampered-pkg',
      },
    ];

    const report = engine.evaluate('tampered-pkg', '1.0.0', evidence, 'Unverified');
    expect(report.verdict).toBe('Block');
    expect(report.hardBlocks.length).toBeGreaterThan(0);
    expect(report.hardBlocks[0]).toContain('Integrity verification failed');
  });

  it('missing provenance alone is not malicious and results in PartiallyVerified without hard blocks', () => {
    const evidence: Evidence[] = [];
    const status: VerificationStatus = 'PartiallyVerified';
    const report = engine.evaluate('clean-legacy-pkg', '1.0.0', evidence, status);
    expect(report.verdict).toBe('Safe');
    expect(report.riskScore).toBe(100);
    expect(report.hardBlocks.length).toBe(0);
    expect(report.verificationStatus).toBe('PartiallyVerified');
  });

  it('hard-blocks on critical vulnerability or correlated exfiltration pattern in lifecycle script', () => {
    const evidence: Evidence[] = [
      {
        id: 'ev-vuln',
        scanner: 'VulnScanner',
        category: 'vulnerability',
        severity: 'CRITICAL',
        confidence: 0.95,
        description: 'RCE in core parser',
        dedupKey: 'vuln:core:rce',
      },
      {
        id: 'ev-exfil',
        scanner: 'StaticAnalyzer',
        category: 'static-analysis',
        severity: 'CRITICAL',
        confidence: 0.98,
        description: 'Correlated credential exfiltration pattern in install script',
        dedupKey: 'static:correlated:exfiltration:setup.js',
      },
      {
        id: 'ev-typo',
        scanner: 'TyposquatScanner',
        category: 'typosquat',
        severity: 'HIGH',
        confidence: 0.9,
        description: 'Typosquat of lodash',
        dedupKey: 'typosquat:lodahs:lodash',
      },
    ];

    const report = engine.evaluate('evil-pkg', '1.0.1', evidence, 'PartiallyVerified', ['Custom policy ban']);
    expect(report.verdict).toBe('Block');
    expect(report.hardBlocks.some((h) => h.includes('Critical vulnerability'))).toBe(true);
    expect(report.hardBlocks.some((h) => h.includes('Correlated credential exfiltration'))).toBe(true);
    expect(report.hardBlocks.some((h) => h.includes('Custom policy ban'))).toBe(true);
    expect(report.remediation.length).toBeGreaterThanOrEqual(3);
  });

  it('renders terminal text with policy violations, breakdowns, snippets, and sources', () => {
    const report = engine.evaluate('full-pkg', '1.0.0', [
      {
        id: 'ev-1',
        scanner: 'MetadataScanner',
        category: 'metadata',
        severity: 'MEDIUM',
        confidence: 0.8,
        description: 'Script present',
        dedupKey: 'key-1',
        location: { file: 'package.json', line: 12 },
        snippet: '"postinstall": "node setup.js"',
        sources: ['MetadataScanner', 'VersionDiffScanner'],
      },
    ], 'Verified');

    report.policyApplied = {
      name: 'strict',
      passed: false,
      violations: ['Banned install script'],
    };

    const term = renderTerminalReport(report);
    expect(term).toContain('PACKAGEGUARD TRUST REPORT: full-pkg@1.0.0');
    expect(term).toContain('Policy Status:       FAILED');
    expect(term).toContain('Banned install script');
    expect(term).toContain('Snippet: "postinstall": "node setup.js"');
    expect(term).toContain('Corroborated by: MetadataScanner, VersionDiffScanner');

    const jsonStr = renderJsonReport(report);
    const parsed = JSON.parse(jsonStr);
    expect(parsed.package).toBe('full-pkg');
    expect(parsed.policyApplied.passed).toBe(false);
  });
});

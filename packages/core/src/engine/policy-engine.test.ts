import { describe, it, expect } from 'vitest';
import { PolicyEngine, parsePolicyYaml } from './policy-engine.js';
import type { Evidence } from '../types.js';

describe('PolicyEngine and YAML Policy Loader', () => {
  it('parses valid policy YAML', () => {
    const yaml = `
minScore: 85
requireProvenance: true
banInstallScripts: true
minVerificationStatus: PartiallyVerified
allowlist:
  - react
  - react-dom
`;
    const policy = parsePolicyYaml(yaml);
    expect(policy.minScore).toBe(85);
    expect(policy.requireProvenance).toBe(true);
    expect(policy.banInstallScripts).toBe(true);
    expect(policy.allowlist).toContain('react');
  });

  it('bypasses checks for allowlisted packages', () => {
    const engine = new PolicyEngine({
      minScore: 90,
      banInstallScripts: true,
      allowlist: ['trusted-corp-pkg'],
    });

    const res = engine.evaluate('trusted-corp-pkg', '1.0.0', 50, 'Unverified', [
      {
        id: 'ev-script',
        scanner: 'MetadataScanner',
        category: 'metadata',
        severity: 'MEDIUM',
        confidence: 0.9,
        description: 'postinstall',
        dedupKey: 'lifecycle:script:postinstall',
      },
    ]);

    expect(res.passed).toBe(true);
    expect(res.isAllowed).toBe(true);
    expect(res.violations.length).toBe(0);
  });

  it('enforces minScore, banInstallScripts and minVerificationStatus', () => {
    const engine = new PolicyEngine({
      minScore: 85,
      banInstallScripts: true,
      minVerificationStatus: 'PartiallyVerified',
      requireProvenance: true,
    });

    const scriptEv: Evidence = {
      id: 'e1',
      scanner: 'MetadataScanner',
      category: 'metadata',
      severity: 'MEDIUM',
      confidence: 0.9,
      description: 'postinstall',
      dedupKey: 'lifecycle:script:postinstall',
    };

    const res = engine.evaluate('test-pkg', '1.0.0', 70, 'Unverified', [scriptEv]);
    expect(res.passed).toBe(false);
    expect(res.violations.length).toBe(4);
    expect(res.hardBlocks.length).toBeGreaterThan(0);
    expect(res.violations[0]).toContain('below policy minimum required score');
    expect(res.violations[1]).toContain('does not meet required minimum');
    expect(res.violations[2]).toContain('provenance attestation is required');
    expect(res.violations[3]).toContain('strictly bans packages with install scripts');
  });

  it('throws on invalid yaml', () => {
    expect(() => parsePolicyYaml(':\n:invalid')).toThrow('Failed to parse policy YAML');
  });
});

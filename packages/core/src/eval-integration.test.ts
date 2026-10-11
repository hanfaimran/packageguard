import crypto from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { scanPackage, type ScanContext } from './index.js';
import { generateAllFixtures } from '../../../eval/src/fixtures/generator.js';

describe('End-to-End Evaluation Integration Test', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

  const fixtures = generateAllFixtures(privPem);

  it('scans clean-pkg@1.0.0 and issues Safe verdict with 100 risk score', async () => {
    const fixture = fixtures['clean-pkg@1.0.0'];
    const ctx: ScanContext = {
      packageName: 'clean-pkg',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes: fixture.tarballBytes,
      registryMetadata: fixture.packageDocument,
    };

    const report = await scanPackage(ctx, {
      trustedPublicKeys: { 'packageguard-eval-key-1': pubPem },
    });

    expect(report.verdict).toBe('Safe');
    expect(report.riskScore).toBe(100);
    expect(report.hardBlocks).toHaveLength(0);
  });

  it('proves hard-negative benign-tool@1.0.0 (uses child_process and process.env legitimately) is NOT Blocked and receives Safe verdict', async () => {
    const fixture = fixtures['benign-tool@1.0.0'];
    const ctx: ScanContext = {
      packageName: 'benign-tool',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes: fixture.tarballBytes,
      registryMetadata: fixture.packageDocument,
    };

    const report = await scanPackage(ctx, {
      trustedPublicKeys: { 'packageguard-eval-key-1': pubPem },
    });

    expect(report.verdict).not.toBe('Block');
    expect(report.verdict).toBe('Safe');
    expect(report.riskScore).toBeGreaterThanOrEqual(80);
    expect(report.hardBlocks).toHaveLength(0);
  });

  it('detects tampered-pkg@1.0.0 digest mismatch and immediately issues Block verdict', async () => {
    const fixture = fixtures['tampered-pkg@1.0.0'];
    const ctx: ScanContext = {
      packageName: 'tampered-pkg',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes: fixture.tarballBytes,
      registryMetadata: fixture.packageDocument,
    };

    const report = await scanPackage(ctx, {
      trustedPublicKeys: { 'packageguard-eval-key-1': pubPem },
    });

    expect(report.verdict).toBe('Block');
    expect(report.verificationStatus).toBe('Unverified');
    expect(report.hardBlocks.some((h) => h.includes('Integrity verification failed'))).toBe(true);
  });

  it('detects lodahs@1.0.0 typosquatting and issues Review verdict with explainable reasoning', async () => {
    const fixture = fixtures['lodahs@1.0.0'];
    const ctx: ScanContext = {
      packageName: 'lodahs',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes: fixture.tarballBytes,
      registryMetadata: fixture.packageDocument,
    };

    const report = await scanPackage(ctx, {
      trustedPublicKeys: { 'packageguard-eval-key-1': pubPem },
    });

    expect(report.verdict).toBe('Review');
    const typoEv = report.evidence.find((e) => e.category === 'typosquat');
    expect(typoEv).toBeDefined();
    expect(typoEv?.description).toContain('lodash');
  });

  it('scans event-stream-lite@1.0.1 with version diff against 1.0.0, emits static-analysis evidence with file and line, and issues Block verdict with hard-block reason', async () => {
    const v1 = fixtures['event-stream-lite@1.0.0'];
    const v2 = fixtures['event-stream-lite@1.0.1'];

    const ctx: ScanContext = {
      packageName: 'event-stream-lite',
      ecosystem: 'npm',
      version: '1.0.1',
      tarballBytes: v2.tarballBytes,
      registryMetadata: v2.packageDocument,
      previousVersionTarballBytes: v1.tarballBytes,
      previousVersionMetadata: v1.packageDocument,
    };

    const report = await scanPackage(ctx, {
      trustedPublicKeys: { 'packageguard-eval-key-1': pubPem },
    });

    expect(report.verdict).toBe('Block');
    expect(report.hardBlocks.length).toBeGreaterThan(0);
    expect(
      report.hardBlocks.some((h) => h.includes('Correlated credential exfiltration detected in package')),
    ).toBe(true);

    const staticEv = report.evidence.find(
      (e) => e.category === 'static-analysis' && e.severity === 'CRITICAL',
    );
    expect(staticEv).toBeDefined();
    expect(staticEv?.location?.file).toBe('scripts/postinstall.js');
    expect(staticEv?.location?.line).toBeGreaterThanOrEqual(1);

    expect(report.evidence.some((e) => e.dedupKey === 'lifecycle:script:postinstall')).toBe(true);
    expect(report.evidence.some((e) => e.dedupKey.startsWith('version-diff:maintainer:added'))).toBe(true);
  });

  it('proves hard-negative benign-base64@1.0.0 is NOT Blocked and receives Safe verdict', async () => {
    const fixture = fixtures['benign-base64@1.0.0'];
    const ctx: ScanContext = {
      packageName: 'benign-base64',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes: fixture.tarballBytes,
      registryMetadata: fixture.packageDocument,
    };

    const report = await scanPackage(ctx, {
      trustedPublicKeys: { 'packageguard-eval-key-1': pubPem },
    });

    expect(report.verdict).not.toBe('Block');
    expect(report.verdict).toBe('Safe');
    expect(report.hardBlocks).toHaveLength(0);
  });

  it('proves hard-negative benign-native-postinstall@1.0.0 is NOT Blocked and receives Safe verdict', async () => {
    const fixture = fixtures['benign-native-postinstall@1.0.0'];
    const ctx: ScanContext = {
      packageName: 'benign-native-postinstall',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes: fixture.tarballBytes,
      registryMetadata: fixture.packageDocument,
    };

    const report = await scanPackage(ctx, {
      trustedPublicKeys: { 'packageguard-eval-key-1': pubPem },
    });

    expect(report.verdict).not.toBe('Block');
    expect(report.verdict).toBe('Safe');
    expect(report.hardBlocks).toHaveLength(0);
  });
});

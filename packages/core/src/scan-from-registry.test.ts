import crypto from 'node:crypto';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { scanFromRegistry } from './index.js';
import { generateAllFixtures } from '../../../eval/src/fixtures/generator.js';
import { FakeRegistryServer } from '../../../eval/src/fake-registry.js';

describe('scanFromRegistry', () => {
  let server: FakeRegistryServer;
  let serverUrl: string;
  let pubPem: string;

  beforeAll(async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });
    pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

    const fixtures = generateAllFixtures(privPem);
    server = new FakeRegistryServer({ port: 4005, fixtures });
    serverUrl = await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('scans clean-pkg@1.0.0 directly from registry and returns Safe verdict', async () => {
    const report = await scanFromRegistry('clean-pkg', '1.0.0', {
      registryUrl: serverUrl,
      trustedPublicKeys: { 'packageguard-eval-key-1': pubPem },
    });

    expect(report.verdict).toBe('Safe');
    expect(report.package).toBe('clean-pkg');
    expect(report.version).toBe('1.0.0');
    expect(report.hardBlocks).toHaveLength(0);
    expect(report.riskScore).toBe(100);
  });

  it('scans event-stream-lite@1.0.1 directly from registry with automated version diff against 1.0.0 and returns Block', async () => {
    const report = await scanFromRegistry('event-stream-lite', '1.0.1', {
      registryUrl: serverUrl,
      trustedPublicKeys: { 'packageguard-eval-key-1': pubPem },
    });

    expect(report.verdict).toBe('Block');
    expect(report.package).toBe('event-stream-lite');
    expect(report.version).toBe('1.0.1');
    expect(report.hardBlocks.length).toBeGreaterThan(0);
    expect(
      report.hardBlocks.some((h) => h.includes('Correlated credential exfiltration detected in package')),
    ).toBe(true);

    const staticEv = report.evidence.find(
      (e) => e.category === 'static-analysis' && e.severity === 'CRITICAL',
    );
    expect(staticEv).toBeDefined();
    expect(staticEv?.location?.file).toBe('scripts/postinstall.js');
  });

  it('throws helpful error when version is not in registry', async () => {
    await expect(
      scanFromRegistry('clean-pkg', '9.9.9', { registryUrl: serverUrl }),
    ).rejects.toThrow('Version 9.9.9 of package clean-pkg not found in registry');
  });

  it('throws helpful error when package does not exist', async () => {
    await expect(
      scanFromRegistry('nonexistent-pkg-xyz', '1.0.0', { registryUrl: serverUrl }),
    ).rejects.toThrow('Failed to fetch package metadata from registry');
  });
});

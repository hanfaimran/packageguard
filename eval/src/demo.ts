import crypto from 'node:crypto';
import { scanPackage, renderTerminalReport, type ScanContext } from '@packageguard/core';
import { generateAllFixtures } from './fixtures/generator.js';
import { FakeRegistryServer } from './fake-registry.js';

export async function runDemo(): Promise<void> {
  console.log('🚀 Running PackageGuard Demo on event-stream-lite@1.0.1 against Fake Registry...');

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

  const fixtures = generateAllFixtures(privPem);
  const server = new FakeRegistryServer({ port: 4002, fixtures });
  const serverUrl = await server.start();

  try {
    const v1Fixture = fixtures['event-stream-lite@1.0.0'];
    const v2Fixture = fixtures['event-stream-lite@1.0.1'];

    const ctx: ScanContext = {
      packageName: 'event-stream-lite',
      ecosystem: 'npm',
      version: '1.0.1',
      tarballBytes: v2Fixture.tarballBytes,
      registryMetadata: v2Fixture.packageDocument,
      previousVersionTarballBytes: v1Fixture.tarballBytes,
      previousVersionMetadata: v1Fixture.packageDocument,
      registryUrl: serverUrl,
    };

    const report = await scanPackage(ctx, {
      trustedPublicKeys: { 'packageguard-eval-key-1': pubPem },
    });

    console.log(renderTerminalReport(report));
  } finally {
    await server.stop();
  }
}

runDemo().catch((err) => {
  console.error('Demo error:', err);
  process.exit(1);
});

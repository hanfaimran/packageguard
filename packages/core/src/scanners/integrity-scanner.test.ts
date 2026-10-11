import crypto from 'node:crypto';
import { describe, it, expect, vi } from 'vitest';
import { IntegrityScanner } from './integrity-scanner.js';
import type { ScanContext } from '../types.js';

describe('IntegrityScanner', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

  it('verifies valid tarball SHA-512 and registry signature and provenance => Verified', async () => {
    const tarballBytes = Buffer.from('console.log("hello world");');
    const hash = crypto.createHash('sha512').update(tarballBytes).digest('base64');
    const integrity = `sha512-${hash}`;

    const signer = crypto.createSign('SHA256');
    signer.update(`valid-pkg@1.0.0:${integrity}`);
    const sig = signer.sign(privateKey, 'base64');

    const mockSigstoreVerifier = vi.fn().mockResolvedValue(true);

    const scanner = new IntegrityScanner({ 'key-test-1': pubPem }, mockSigstoreVerifier);

    const ctx: ScanContext = {
      packageName: 'valid-pkg',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes,
      registryMetadata: {
        versions: {
          '1.0.0': {
            name: 'valid-pkg',
            version: '1.0.0',
            dist: {
              integrity,
              signatures: [{ keyid: 'key-test-1', sig }],
              attestations: {
                provenance: { bundle: { mediaType: 'mock' } },
              },
            },
          },
        },
      },
    };

    const result = await scanner.verify(ctx);
    expect(result.status).toBe('Verified');
    expect(result.hashMatch).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.provenanceVerified).toBe(true);
    expect(result.evidence.length).toBe(0);
  });

  it('marks PartiallyVerified when hash matches but provenance or signature unavailable, not malicious', async () => {
    const tarballBytes = Buffer.from('console.log("partially verified");');
    const hash = crypto.createHash('sha512').update(tarballBytes).digest('base64');
    const integrity = `sha512-${hash}`;

    const scanner = new IntegrityScanner({});
    const ctx: ScanContext = {
      packageName: 'legacy-pkg',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes,
      registryMetadata: {
        dist: {
          integrity,
        },
      },
    };

    const result = await scanner.verify(ctx);
    expect(result.status).toBe('PartiallyVerified');
    expect(result.hashMatch).toBe(true);
    expect(result.signatureValid).toBe(false);
    expect(result.provenanceVerified).toBe(false);
    // Missing provenance alone is NOT emitted as malicious evidence
    expect(result.evidence.length).toBe(0);
  });

  it('detects tarball digest mismatch and explicitly reports expected vs actual => Unverified with CRITICAL evidence', async () => {
    const tamperedBytes = Buffer.from('console.log("tampered payload!");');
    const expectedHash = crypto.createHash('sha512').update(Buffer.from('original')).digest('base64');
    const expectedDigest = `sha512-${expectedHash}`;

    const scanner = new IntegrityScanner({});
    const ctx: ScanContext = {
      packageName: 'tampered-pkg',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes: tamperedBytes,
      registryMetadata: {
        dist: {
          integrity: expectedDigest,
        },
      },
    };

    const result = await scanner.verify(ctx);
    expect(result.status).toBe('Unverified');
    expect(result.hashMatch).toBe(false);
    expect(result.computedSha512).not.toBe(expectedDigest);
    expect(result.evidence.length).toBe(1);

    const ev = result.evidence[0];
    expect(ev.category).toBe('integrity');
    expect(ev.severity).toBe('CRITICAL');
    expect(ev.rawData?.expected).toBe(expectedDigest);
    expect(ev.rawData?.actual).toBe(result.computedSha512);
  });

  it('detects invalid registry ECDSA signature when trusted public key is known', async () => {
    const tarballBytes = Buffer.from('safe code');
    const hash = crypto.createHash('sha512').update(tarballBytes).digest('base64');
    const integrity = `sha512-${hash}`;

    const scanner = new IntegrityScanner({ 'key-test-1': pubPem });
    const ctx: ScanContext = {
      packageName: 'bad-sig-pkg',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes,
      registryMetadata: {
        dist: {
          integrity,
          signatures: [{ keyid: 'key-test-1', sig: 'invalidsignaturebase64==' }],
        },
      },
    };

    const result = await scanner.verify(ctx);
    expect(result.status).toBe('Unverified');
    expect(result.signatureValid).toBe(false);
    expect(result.evidence.some((e) => e.dedupKey.startsWith('integrity:invalid-sig'))).toBe(true);
  });

  it('handles missing tarball bytes and missing expected digest in registry', async () => {
    const scanner = new IntegrityScanner({});
    const resNoBytes = await scanner.verify({
      packageName: 'p1',
      ecosystem: 'npm',
      version: '1.0.0',
    });
    expect(resNoBytes.status).toBe('Unverified');
    expect(resNoBytes.evidence[0].dedupKey).toBe('integrity:missing-tarball:p1');

    const resNoDigest = await scanner.verify({
      packageName: 'p2',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes: Buffer.from('data'),
      registryMetadata: {},
    });
    expect(resNoDigest.status).toBe('Unverified');
    expect(resNoDigest.evidence[0].dedupKey).toBe('integrity:no-expected-digest:p2');
  });

  it('handles sigstore library verification error gracefully', async () => {
    const tarballBytes = Buffer.from('some content');
    const hash = crypto.createHash('sha512').update(tarballBytes).digest('base64');
    const integrity = `sha512-${hash}`;

    const scanner = new IntegrityScanner({});
    const ctx: ScanContext = {
      packageName: 'sigstore-err',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes,
      registryMetadata: {
        dist: {
          integrity,
          attestations: {
            provenance: { bundle: { invalid: 'bundle' } },
          },
        },
      },
    };

    const result = await scanner.verify(ctx);
    expect(result.provenanceVerified).toBe(false);
    expect(result.status).toBe('PartiallyVerified');
  });
});

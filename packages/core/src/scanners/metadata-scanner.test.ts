import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { MetadataScanner } from './metadata-scanner.js';
import { RegistryClient } from '../clients/registry-client.js';
import type { ScanContext } from '../types.js';

describe('MetadataScanner & RegistryClient', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('RegistryClient fetches and parses package document including scoped package', async () => {
    const mockDoc = {
      name: '@scope/pkg',
      versions: {},
    };
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockDoc,
      arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer,
    } as any);

    const client = new RegistryClient('https://registry.npmjs.org/');
    const doc = await client.getPackageDocument('@scope/pkg');
    expect(doc.name).toBe('@scope/pkg');

    const tarballBytes = await client.downloadTarball('https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz');
    expect(tarballBytes.length).toBe(3);
  });

  it('RegistryClient throws on HTTP failure', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
    } as any);

    const client = new RegistryClient();
    await expect(client.getPackageDocument('missing-pkg')).rejects.toThrow('Failed to fetch package metadata');
    await expect(client.downloadTarball('https://invalid.url')).rejects.toThrow('Failed to download tarball');
  });

  it('MetadataScanner returns empty evidence if no registry metadata provided', async () => {
    const scanner = new MetadataScanner();
    const ctx: ScanContext = {
      packageName: 'empty-ctx',
      ecosystem: 'npm',
      version: '1.0.0',
    };
    const evidence = await scanner.collect(ctx);
    expect(evidence).toEqual([]);
  });

  it('MetadataScanner detects young age, missing repo, install script, few maintainers', async () => {
    const scanner = new MetadataScanner();
    const now = new Date();
    const tenDaysAgo = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000).toISOString();

    const ctx: ScanContext = {
      packageName: 'suspicious-pkg',
      ecosystem: 'npm',
      version: '1.0.0',
      registryMetadata: {
        name: 'suspicious-pkg',
        time: {
          created: tenDaysAgo,
          '1.0.0': tenDaysAgo,
        },
        maintainers: [{ name: 'lone-wolf' }],
        versions: {
          '1.0.0': {
            name: 'suspicious-pkg',
            version: '1.0.0',
            scripts: {
              postinstall: 'node setup.js',
              preinstall: 'node pre.js',
            },
          },
        },
      },
    };

    const evidence = await scanner.collect(ctx);
    expect(evidence.length).toBe(5);

    const ageEv = evidence.find((e) => e.dedupKey.startsWith('metadata:age'));
    expect(ageEv).toBeDefined();
    expect(ageEv?.severity).toBe('LOW');

    const repoEv = evidence.find((e) => e.dedupKey.startsWith('metadata:repo'));
    expect(repoEv).toBeDefined();

    const scriptEv = evidence.find((e) => e.dedupKey === 'lifecycle:script:postinstall');
    expect(scriptEv).toBeDefined();
    expect(scriptEv?.severity).toBe('MEDIUM');

    const maintEv = evidence.find((e) => e.dedupKey.startsWith('metadata:maintainers'));
    expect(maintEv).toBeDefined();
  });

  it('MetadataScanner handles string repo format and unreleased version fallback', async () => {
    const scanner = new MetadataScanner();
    const now = new Date();
    const fiveDaysAgo = new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000).toISOString();

    const ctx: ScanContext = {
      packageName: 'pkg-string-repo',
      ecosystem: 'npm',
      version: '1.0.0',
      registryMetadata: {
        name: 'pkg-string-repo',
        repository: 'git+https://github.com/foo/bar.git',
        time: {
          created: fiveDaysAgo,
        },
        versions: {},
      },
    };

    const evidence = await scanner.collect(ctx);
    // repo is present, so no repo evidence.
    // 0 maintainers => few maintainers
    // age < 30 days based on created => young age
    expect(evidence.some((e) => e.dedupKey.startsWith('metadata:repo'))).toBe(false);
    expect(evidence.some((e) => e.dedupKey.startsWith('metadata:age'))).toBe(true);
    expect(evidence.some((e) => e.dedupKey.startsWith('metadata:maintainers'))).toBe(true);
  });

  it('MetadataScanner emits no evidence for established package with multiple maintainers, repo, no scripts', async () => {
    const scanner = new MetadataScanner();
    const oldDate = '2020-01-01T00:00:00.000Z';

    const ctx: ScanContext = {
      packageName: 'clean-pkg',
      ecosystem: 'npm',
      version: '2.0.0',
      registryMetadata: {
        name: 'clean-pkg',
        time: {
          created: oldDate,
          '2.0.0': oldDate,
        },
        repository: { type: 'git', url: 'https://github.com/clean/clean-pkg' },
        maintainers: [{ name: 'alice' }, { name: 'bob' }],
        versions: {
          '2.0.0': {
            name: 'clean-pkg',
            version: '2.0.0',
            repository: { type: 'git', url: 'https://github.com/clean/clean-pkg' },
            maintainers: [{ name: 'alice' }, { name: 'bob' }],
            scripts: {
              test: 'vitest',
            },
          },
        },
      },
    };

    const evidence = await scanner.collect(ctx);
    expect(evidence.length).toBe(0);
  });
});

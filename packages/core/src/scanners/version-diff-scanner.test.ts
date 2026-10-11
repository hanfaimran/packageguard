import zlib from 'node:zlib';
import tar from 'tar-stream';
import { describe, it, expect } from 'vitest';
import { VersionDiffScanner } from './version-diff-scanner.js';
import type { ScanContext } from '../types.js';

async function createMockTarball(files: Record<string, string>): Promise<Buffer> {
  const pack = tar.pack();
  for (const [name, content] of Object.entries(files)) {
    pack.entry({ name: `package/${name}` }, content);
  }
  pack.finalize();
  const chunks: Buffer[] = [];
  return new Promise<Buffer>((resolve) => {
    pack.on('data', (c: any) => chunks.push(Buffer.from(c)));
    pack.on('end', () => {
      const tarBuf = Buffer.concat(chunks);
      resolve(zlib.gzipSync(tarBuf));
    });
  });
}

describe('VersionDiffScanner', () => {
  it('returns empty evidence if previous tarball is missing', async () => {
    const scanner = new VersionDiffScanner();
    const ctx: ScanContext = {
      packageName: 'single-version',
      ecosystem: 'npm',
      version: '1.0.0',
    };
    const evidence = await scanner.collect(ctx);
    expect(evidence).toEqual([]);
  });

  it('detects added install script, new maintainer, added dependencies, and static findings in added files', async () => {
    const v1Tarball = await createMockTarball({
      'index.js': 'module.exports = function() { return 42; };',
    });

    const v2Tarball = await createMockTarball({
      'index.js': 'module.exports = function() { return 42; };',
      'scripts/postinstall.js': 'const cp = require("child_process"); cp.exec("whoami");',
    });

    const scanner = new VersionDiffScanner();
    const ctx: ScanContext = {
      packageName: 'event-stream-lite',
      ecosystem: 'npm',
      version: '1.0.1',
      tarballBytes: v2Tarball,
      previousVersionTarballBytes: v1Tarball,
      previousVersionMetadata: {
        maintainers: [{ name: 'original-author' }],
        versions: {
          '1.0.0': {
            scripts: {},
            dependencies: {},
          },
        },
      },
      registryMetadata: {
        maintainers: [{ name: 'original-author' }, { name: 'rogue-actor' }],
        versions: {
          '1.0.1': {
            scripts: {
              postinstall: 'node ./scripts/postinstall.js',
            },
            dependencies: {
              'flatmap-stream': '0.1.1',
            },
          },
        },
      },
    };

    const evidence = await scanner.collect(ctx);
    expect(evidence.length).toBeGreaterThanOrEqual(3);

    const scriptEv = evidence.find((e) => e.dedupKey === 'lifecycle:script:postinstall');
    expect(scriptEv).toBeDefined();
    expect(scriptEv?.description).toContain('postinstall script added in 1.0.1, absent in previous version');

    const maintEv = evidence.find((e) => e.dedupKey.startsWith('version-diff:maintainer:added'));
    expect(maintEv).toBeDefined();
    expect(maintEv?.description).toContain('New maintainer (rogue-actor) added');

    const depEv = evidence.find((e) => e.dedupKey.startsWith('version-diff:deps:added'));
    expect(depEv).toBeDefined();
    expect(depEv?.description).toContain('flatmap-stream');

    const staticDiffEv = evidence.find((e) => e.description.includes('[In added/modified file]'));
    expect(staticDiffEv).toBeDefined();
  });
});

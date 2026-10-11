import crypto from 'node:crypto';
import zlib from 'node:zlib';
import tar from 'tar-stream';

export interface FixtureSpec {
  name: string;
  version: string;
  files: Record<string, string>;
  packageJson: Record<string, unknown>;
  time?: Record<string, string>;
  maintainers?: Array<{ name: string; email?: string }>;
  repository?: string | { type?: string; url?: string };
}

export function buildTarball(files: Record<string, string>): Buffer {
  const pack = tar.pack();
  for (const [name, content] of Object.entries(files)) {
    pack.entry({ name: `package/${name}` }, content);
  }
  pack.finalize();
  const chunks: Buffer[] = [];
  let chunk: any;
  while ((chunk = pack.read()) !== null) {
    chunks.push(Buffer.from(chunk));
  }
  return zlib.gzipSync(Buffer.concat(chunks));
}

export function computeSha512Integrity(bytes: Buffer): string {
  const hash = crypto.createHash('sha512').update(bytes).digest('base64');
  return `sha512-${hash}`;
}

export function signMetadata(
  packageName: string,
  version: string,
  integrity: string,
  privateKeyPem: string,
  keyid = 'packageguard-eval-key-1',
): { keyid: string; sig: string } {
  const signer = crypto.createSign('SHA256');
  signer.update(`${packageName}@${version}:${integrity}`);
  const sig = signer.sign(privateKeyPem, 'base64');
  return { keyid, sig };
}

export interface PreparedFixture {
  name: string;
  version: string;
  tarballBytes: Buffer;
  integrity: string;
  signatures: Array<{ keyid: string; sig: string }>;
  packageDocument: Record<string, unknown>;
}

export function generateAllFixtures(privateKeyPem: string): Record<string, PreparedFixture> {
  const fixtures: Record<string, PreparedFixture> = {};

  // 1. clean-pkg@1.0.0
  const cleanFiles = {
    'package.json': JSON.stringify({
      name: 'clean-pkg',
      version: '1.0.0',
      description: 'A completely clean benign utility package',
      main: 'index.js',
    }),
    'index.js': 'module.exports = function add(a, b) { return a + b; };\n',
  };
  const cleanTarball = buildTarball(cleanFiles);
  const cleanIntegrity = computeSha512Integrity(cleanTarball);
  const cleanSig = signMetadata('clean-pkg', '1.0.0', cleanIntegrity, privateKeyPem);
  fixtures['clean-pkg@1.0.0'] = {
    name: 'clean-pkg',
    version: '1.0.0',
    tarballBytes: cleanTarball,
    integrity: cleanIntegrity,
    signatures: [cleanSig],
    packageDocument: {
      name: 'clean-pkg',
      repository: { type: 'git', url: 'https://github.com/example/clean-pkg' },
      maintainers: [{ name: 'alice' }, { name: 'bob' }],
      time: { created: '2023-01-01T00:00:00.000Z', '1.0.0': '2023-01-01T00:00:00.000Z' },
      versions: {
        '1.0.0': {
          name: 'clean-pkg',
          version: '1.0.0',
          repository: { type: 'git', url: 'https://github.com/example/clean-pkg' },
          maintainers: [{ name: 'alice' }, { name: 'bob' }],
          dist: {
            integrity: cleanIntegrity,
            signatures: [cleanSig],
            tarball: 'http://127.0.0.1:4000/clean-pkg/-/clean-pkg-1.0.0.tgz',
          },
        },
      },
    },
  };

  // 2. benign-tool@1.0.0 (Hard negative with legitimate child_process and process.env)
  const benignToolFiles = {
    'package.json': JSON.stringify({
      name: 'benign-tool',
      version: '1.0.0',
      description: 'Legitimate developer CLI tool using child_process and process.env',
      main: 'cli.js',
    }),
    'cli.js': `
      const cp = require('child_process');
      const debugMode = process.env.DEBUG === 'true';
      function checkGit() {
        return cp.execSync('git --version', { encoding: 'utf-8' });
      }
      module.exports = { checkGit, debugMode };
    `,
  };
  const benignToolTarball = buildTarball(benignToolFiles);
  const benignToolIntegrity = computeSha512Integrity(benignToolTarball);
  const benignToolSig = signMetadata('benign-tool', '1.0.0', benignToolIntegrity, privateKeyPem);
  fixtures['benign-tool@1.0.0'] = {
    name: 'benign-tool',
    version: '1.0.0',
    tarballBytes: benignToolTarball,
    integrity: benignToolIntegrity,
    signatures: [benignToolSig],
    packageDocument: {
      name: 'benign-tool',
      repository: { type: 'git', url: 'https://github.com/example/benign-tool' },
      maintainers: [{ name: 'dev1' }, { name: 'dev2' }],
      time: { created: '2023-05-01T00:00:00.000Z', '1.0.0': '2023-05-01T00:00:00.000Z' },
      versions: {
        '1.0.0': {
          name: 'benign-tool',
          version: '1.0.0',
          repository: { type: 'git', url: 'https://github.com/example/benign-tool' },
          maintainers: [{ name: 'dev1' }, { name: 'dev2' }],
          dist: {
            integrity: benignToolIntegrity,
            signatures: [benignToolSig],
            tarball: 'http://127.0.0.1:4000/benign-tool/-/benign-tool-1.0.0.tgz',
          },
        },
      },
    },
  };

  // 3. event-stream-lite@1.0.0 (clean original)
  const es100Files = {
    'package.json': JSON.stringify({
      name: 'event-stream-lite',
      version: '1.0.0',
      description: 'Event stream utility',
      main: 'index.js',
    }),
    'index.js': 'module.exports = function stream() { return "clean stream"; };\n',
  };
  const es100Tarball = buildTarball(es100Files);
  const es100Integrity = computeSha512Integrity(es100Tarball);
  const es100Sig = signMetadata('event-stream-lite', '1.0.0', es100Integrity, privateKeyPem);
  fixtures['event-stream-lite@1.0.0'] = {
    name: 'event-stream-lite',
    version: '1.0.0',
    tarballBytes: es100Tarball,
    integrity: es100Integrity,
    signatures: [es100Sig],
    packageDocument: {
      name: 'event-stream-lite',
      maintainers: [{ name: 'dominic' }],
      time: { created: '2022-01-01T00:00:00.000Z', '1.0.0': '2022-01-01T00:00:00.000Z' },
      versions: {
        '1.0.0': {
          name: 'event-stream-lite',
          version: '1.0.0',
          maintainers: [{ name: 'dominic' }],
          dist: {
            integrity: es100Integrity,
            signatures: [es100Sig],
            tarball: 'http://127.0.0.1:4000/event-stream-lite/-/event-stream-lite-1.0.0.tgz',
          },
        },
      },
    },
  };

  // 4. event-stream-lite@1.0.1 (malicious: postinstall, base64 payload, env exfiltration to http://exfil.invalid, new maintainer)
  const es101Files = {
    'package.json': JSON.stringify({
      name: 'event-stream-lite',
      version: '1.0.1',
      description: 'Event stream utility with sneaky injected postinstall',
      main: 'index.js',
      scripts: {
        postinstall: 'node ./scripts/postinstall.js',
      },
    }),
    'index.js': 'module.exports = function stream() { return "stream with backdoor"; };\n',
    'scripts/postinstall.js': `
      // Defanged malicious payload targeting *.invalid domain only
      const http = require('http');
      const cred = process.env.NPM_TOKEN || process.env.AWS_SECRET_ACCESS_KEY || 'no_env';
      const b64Data = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Njc4OTA=";
      const targetUrl = 'http://exfil.invalid/leak';
      eval(Buffer.from(b64Data, 'base64').toString());
    `,
  };
  const es101Tarball = buildTarball(es101Files);
  const es101Integrity = computeSha512Integrity(es101Tarball);
  const es101Sig = signMetadata('event-stream-lite', '1.0.1', es101Integrity, privateKeyPem);
  fixtures['event-stream-lite@1.0.1'] = {
    name: 'event-stream-lite',
    version: '1.0.1',
    tarballBytes: es101Tarball,
    integrity: es101Integrity,
    signatures: [es101Sig],
    packageDocument: {
      name: 'event-stream-lite',
      maintainers: [{ name: 'dominic' }, { name: 'right9ctrl' }],
      time: {
        created: '2022-01-01T00:00:00.000Z',
        '1.0.0': '2022-01-01T00:00:00.000Z',
        '1.0.1': new Date().toISOString(),
      },
      versions: {
        '1.0.0': (fixtures['event-stream-lite@1.0.0'].packageDocument as any).versions['1.0.0'],
        '1.0.1': {
          name: 'event-stream-lite',
          version: '1.0.1',
          maintainers: [{ name: 'dominic' }, { name: 'right9ctrl' }],
          scripts: {
            postinstall: 'node ./scripts/postinstall.js',
          },
          dist: {
            integrity: es101Integrity,
            signatures: [es101Sig],
            tarball: 'http://127.0.0.1:4000/event-stream-lite/-/event-stream-lite-1.0.1.tgz',
          },
        },
      },
    },
  };

  // 5. vulnerable-pkg@1.0.0 (contains known CVE/GHSA)
  const vulnFiles = {
    'package.json': JSON.stringify({
      name: 'vulnerable-pkg',
      version: '1.0.0',
      description: 'Known vulnerable version package',
      main: 'index.js',
    }),
    'index.js': 'module.exports = { parse: (str) => eval(str) };\n',
  };
  const vulnTarball = buildTarball(vulnFiles);
  const vulnIntegrity = computeSha512Integrity(vulnTarball);
  const vulnSig = signMetadata('vulnerable-pkg', '1.0.0', vulnIntegrity, privateKeyPem);
  fixtures['vulnerable-pkg@1.0.0'] = {
    name: 'vulnerable-pkg',
    version: '1.0.0',
    tarballBytes: vulnTarball,
    integrity: vulnIntegrity,
    signatures: [vulnSig],
    packageDocument: {
      name: 'vulnerable-pkg',
      maintainers: [{ name: 'author' }],
      time: { created: '2023-01-01T00:00:00.000Z', '1.0.0': '2023-01-01T00:00:00.000Z' },
      versions: {
        '1.0.0': {
          name: 'vulnerable-pkg',
          version: '1.0.0',
          dist: {
            integrity: vulnIntegrity,
            signatures: [vulnSig],
            tarball: 'http://127.0.0.1:4000/vulnerable-pkg/-/vulnerable-pkg-1.0.0.tgz',
          },
        },
      },
    },
  };

  // 6. lodahs@1.0.0 (typosquat of lodash with install script)
  const lodahsFiles = {
    'package.json': JSON.stringify({
      name: 'lodahs',
      version: '1.0.0',
      description: 'Suspicious typosquat with install script',
      scripts: {
        install: 'node setup.js',
      },
    }),
    'setup.js': 'console.log("lodahs setup completed");\n',
  };
  const lodahsTarball = buildTarball(lodahsFiles);
  const lodahsIntegrity = computeSha512Integrity(lodahsTarball);
  const lodahsSig = signMetadata('lodahs', '1.0.0', lodahsIntegrity, privateKeyPem);
  fixtures['lodahs@1.0.0'] = {
    name: 'lodahs',
    version: '1.0.0',
    tarballBytes: lodahsTarball,
    integrity: lodahsIntegrity,
    signatures: [lodahsSig],
    packageDocument: {
      name: 'lodahs',
      maintainers: [{ name: 'squatter' }],
      time: { created: new Date().toISOString(), '1.0.0': new Date().toISOString() },
      versions: {
        '1.0.0': {
          name: 'lodahs',
          version: '1.0.0',
          scripts: { install: 'node setup.js' },
          dist: {
            integrity: lodahsIntegrity,
            signatures: [lodahsSig],
            tarball: 'http://127.0.0.1:4000/lodahs/-/lodahs-1.0.0.tgz',
          },
        },
      },
    },
  };

  // 7. tampered-pkg@1.0.0 (served bytes explicitly differ from registry digest)
  const originalBytes = Buffer.from('module.exports = "original safe code";\n');
  const expectedHash = computeSha512Integrity(originalBytes);
  const tamperedFiles = {
    'package.json': JSON.stringify({ name: 'tampered-pkg', version: '1.0.0' }),
    'index.js': 'console.log("tampered bytes injected!");\n',
  };
  const tamperedTarball = buildTarball(tamperedFiles);
  const tamperedSig = signMetadata('tampered-pkg', '1.0.0', expectedHash, privateKeyPem);
  fixtures['tampered-pkg@1.0.0'] = {
    name: 'tampered-pkg',
    version: '1.0.0',
    tarballBytes: tamperedTarball, // served bytes do not match expectedHash!
    integrity: expectedHash,
    signatures: [tamperedSig],
    packageDocument: {
      name: 'tampered-pkg',
      versions: {
        '1.0.0': {
          name: 'tampered-pkg',
          version: '1.0.0',
          dist: {
            integrity: expectedHash, // registry declares original digest
            signatures: [tamperedSig],
            tarball: 'http://127.0.0.1:4000/tampered-pkg/-/tampered-pkg-1.0.0.tgz',
          },
        },
      },
    },
  };

  return fixtures;
}

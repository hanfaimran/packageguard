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
  const blocks: Buffer[] = [];

  const writeString = (buf: Buffer, str: string, offset: number, length: number): void => {
    buf.write(str.slice(0, length), offset, 'utf-8');
  };

  for (const [name, content] of Object.entries(files)) {
    const body = Buffer.from(content, 'utf-8');
    const header = Buffer.alloc(512, 0);
    const fullName = `package/${name}`;

    writeString(header, fullName, 0, 100);
    writeString(header, '0000644\0', 100, 8);
    writeString(header, '0000000\0', 108, 8);
    writeString(header, '0000000\0', 116, 8);
    writeString(header, body.length.toString(8).padStart(11, '0') + '\0', 124, 12);
    writeString(header, Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0', 136, 12);
    header.fill(0x20, 148, 156); // checksum placeholder (spaces)
    header.write('0', 156, 'ascii'); // typeflag: regular file
    writeString(header, 'ustar\0', 257, 6);
    writeString(header, '00', 263, 2);

    let checksum = 0;
    for (const byte of header) checksum += byte;
    writeString(header, checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8);

    blocks.push(header, body);
    const padding = (512 - (body.length % 512)) % 512;
    if (padding > 0) blocks.push(Buffer.alloc(padding, 0));
  }

  blocks.push(Buffer.alloc(1024, 0)); // end-of-archive marker
  return zlib.gzipSync(Buffer.concat(blocks));
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

  // 8. benign-base64@1.0.0 (Hard negative legitimately decoding base64 data URLs / assets)
  const benignBase64Files = {
    'package.json': JSON.stringify({
      name: 'benign-base64',
      version: '1.0.0',
      description: 'Utility that decodes base64 assets and data URIs',
      main: 'index.js',
    }),
    'index.js': `
      function decodeDataUrl(uri) {
        // Legitimate base64 decoding without eval or network access
        const b64Data = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";
        const buf = Buffer.from(b64Data, 'base64');
        return buf.toString('utf-8');
      }
      module.exports = { decodeDataUrl };
    `,
  };
  const b64Tarball = buildTarball(benignBase64Files);
  const b64Integrity = computeSha512Integrity(b64Tarball);
  const b64Sig = signMetadata('benign-base64', '1.0.0', b64Integrity, privateKeyPem);
  fixtures['benign-base64@1.0.0'] = {
    name: 'benign-base64',
    version: '1.0.0',
    tarballBytes: b64Tarball,
    integrity: b64Integrity,
    signatures: [b64Sig],
    packageDocument: {
      name: 'benign-base64',
      repository: { type: 'git', url: 'https://github.com/example/benign-base64' },
      maintainers: [{ name: 'art-dev' }],
      time: { created: '2023-01-01T00:00:00.000Z', '1.0.0': '2023-01-01T00:00:00.000Z' },
      versions: {
        '1.0.0': {
          name: 'benign-base64',
          version: '1.0.0',
          repository: { type: 'git', url: 'https://github.com/example/benign-base64' },
          maintainers: [{ name: 'art-dev' }],
          dist: {
            integrity: b64Integrity,
            signatures: [b64Sig],
            tarball: 'http://127.0.0.1:4000/benign-base64/-/benign-base64-1.0.0.tgz',
          },
        },
      },
    },
  };

  // 9. benign-native-postinstall@1.0.0 (Hard negative with legitimate native compile notice / setup)
  const benignNativeFiles = {
    'package.json': JSON.stringify({
      name: 'benign-native-postinstall',
      version: '1.0.0',
      description: 'Native module wrapper with build notice in postinstall',
      main: 'index.js',
      scripts: {
        postinstall: 'node ./scripts/build-notice.js',
      },
    }),
    'index.js': 'module.exports = { isSupported: true };\n',
    'scripts/build-notice.js': `
      // Legitimate postinstall compile check / message without exfiltration
      console.log('Building native dependencies or checking prebuilt binary compatibility...');
    `,
  };
  const nativeTarball = buildTarball(benignNativeFiles);
  const nativeIntegrity = computeSha512Integrity(nativeTarball);
  const nativeSig = signMetadata('benign-native-postinstall', '1.0.0', nativeIntegrity, privateKeyPem);
  fixtures['benign-native-postinstall@1.0.0'] = {
    name: 'benign-native-postinstall',
    version: '1.0.0',
    tarballBytes: nativeTarball,
    integrity: nativeIntegrity,
    signatures: [nativeSig],
    packageDocument: {
      name: 'benign-native-postinstall',
      repository: { type: 'git', url: 'https://github.com/example/benign-native' },
      maintainers: [{ name: 'native-dev' }],
      time: { created: '2023-01-01T00:00:00.000Z', '1.0.0': '2023-01-01T00:00:00.000Z' },
      versions: {
        '1.0.0': {
          name: 'benign-native-postinstall',
          version: '1.0.0',
          repository: { type: 'git', url: 'https://github.com/example/benign-native' },
          maintainers: [{ name: 'native-dev' }],
          scripts: {
            postinstall: 'node ./scripts/build-notice.js',
          },
          dist: {
            integrity: nativeIntegrity,
            signatures: [nativeSig],
            tarball: 'http://127.0.0.1:4000/benign-native-postinstall/-/benign-native-postinstall-1.0.0.tgz',
          },
        },
      },
    },
  };

  return fixtures;
}

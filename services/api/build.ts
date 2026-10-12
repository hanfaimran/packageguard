import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import esbuild from 'esbuild';
import zlib from 'node:zlib';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const distDir = path.resolve(__dirname, 'dist');
const bundleDir = path.resolve(__dirname, 'dist/bundles');
const zipDir = path.resolve(__dirname, '../../infra/build');

if (!fs.existsSync(distDir)) fs.mkdirSync(distDir, { recursive: true });
if (!fs.existsSync(bundleDir)) fs.mkdirSync(bundleDir, { recursive: true });
if (!fs.existsSync(zipDir)) fs.mkdirSync(zipDir, { recursive: true });

/**
 * Minimal standard ZIP writer using standard PKZIP file structure
 */
function createZipWithSingleFile(filename: string, contentBuffer: Buffer): Buffer {
  const date = new Date();
  const dosTime =
    ((date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >> 1)) & 0xffff;
  const dosDate =
    (((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate()) & 0xffff;

  const crcTable: number[] = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    crcTable[n] = c;
  }
  function crc32(buf: Buffer): number {
    let crc = 0 ^ -1;
    for (let i = 0; i < buf.length; i++) {
      crc = (crc >>> 8) ^ crcTable[(crc ^ buf[i]) & 0xff];
    }
    return (crc ^ -1) >>> 0;
  }

  const nameBuf = Buffer.from(filename, 'utf-8');
  const compressed = zlib.deflateRawSync(contentBuffer);
  const crc = crc32(contentBuffer);

  // Local file header (30 + filename length)
  const localHeader = Buffer.alloc(30 + nameBuf.length);
  localHeader.writeUInt32LE(0x04034b50, 0); // local file header signature
  localHeader.writeUInt16LE(20, 4); // version needed to extract
  localHeader.writeUInt16LE(0, 6); // general purpose bit flag
  localHeader.writeUInt16LE(8, 8); // compression method (8 = deflate)
  localHeader.writeUInt16LE(dosTime, 10);
  localHeader.writeUInt16LE(dosDate, 12);
  localHeader.writeUInt32LE(crc, 14);
  localHeader.writeUInt32LE(compressed.length, 18);
  localHeader.writeUInt32LE(contentBuffer.length, 22);
  localHeader.writeUInt16LE(nameBuf.length, 26);
  localHeader.writeUInt16LE(0, 28); // extra field length
  nameBuf.copy(localHeader, 30);

  const localOffset = 0;

  // Central directory header (46 + filename length)
  const cdHeader = Buffer.alloc(46 + nameBuf.length);
  cdHeader.writeUInt32LE(0x02014b50, 0); // central directory signature
  cdHeader.writeUInt16LE(20, 4); // version made by
  cdHeader.writeUInt16LE(20, 6); // version needed to extract
  cdHeader.writeUInt16LE(0, 8); // general purpose bit flag
  cdHeader.writeUInt16LE(8, 10); // compression method (deflate)
  cdHeader.writeUInt16LE(dosTime, 12);
  cdHeader.writeUInt16LE(dosDate, 14);
  cdHeader.writeUInt32LE(crc, 16);
  cdHeader.writeUInt32LE(compressed.length, 20);
  cdHeader.writeUInt32LE(contentBuffer.length, 24);
  cdHeader.writeUInt16LE(nameBuf.length, 28);
  cdHeader.writeUInt16LE(0, 30); // extra field length
  cdHeader.writeUInt16LE(0, 32); // comment length
  cdHeader.writeUInt16LE(0, 34); // disk number start
  cdHeader.writeUInt16LE(0, 36); // internal file attributes
  cdHeader.writeUInt32LE(0, 38); // external file attributes
  cdHeader.writeUInt32LE(localOffset, 42); // relative offset of local header
  nameBuf.copy(cdHeader, 46);

  const cdOffset = localHeader.length + compressed.length;
  const cdSize = cdHeader.length;

  // End of central directory record (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // EOCD signature
  eocd.writeUInt16LE(0, 4); // number of this disk
  eocd.writeUInt16LE(0, 6); // number of disk with start of central directory
  eocd.writeUInt16LE(1, 8); // total number of entries in central directory on this disk
  eocd.writeUInt16LE(1, 10); // total number of entries in central directory
  eocd.writeUInt32LE(cdSize, 12); // size of central directory
  eocd.writeUInt32LE(cdOffset, 16); // offset of start of central directory
  eocd.writeUInt16LE(0, 20); // zipfile comment length

  return Buffer.concat([localHeader, compressed, cdHeader, eocd]);
}

async function zipFile(sourceFile: string, outZip: string): Promise<void> {
  const content = fs.readFileSync(sourceFile);
  const zipBuf = createZipWithSingleFile('index.js', content);
  fs.writeFileSync(outZip, zipBuf);
}

async function bundle() {
  console.log('Bundling Lambda handlers with esbuild...');

  const handlers = [
    { name: 'post-scan', entry: path.resolve(__dirname, 'src/scan-handlers.ts'), exportName: 'postScanHandler' },
    { name: 'get-scan', entry: path.resolve(__dirname, 'src/scan-handlers.ts'), exportName: 'getScanByIdHandler' },
    { name: 'get-history', entry: path.resolve(__dirname, 'src/history-and-scheduled-handlers.ts'), exportName: 'getHistoryHandler' },
    { name: 'nightly-rescan', entry: path.resolve(__dirname, 'src/history-and-scheduled-handlers.ts'), exportName: 'nightlyRescanHandler' },
  ];

  for (const h of handlers) {
    const outJs = path.resolve(bundleDir, `${h.name}.js`);
    const outZip = path.resolve(zipDir, `${h.name}.zip`);

    // Create wrapper entrypoint exporting handler as index.handler
    const wrapperContent = `
      import { ${h.exportName} } from '${h.entry.replace(/\\/g, '/')}';
      export const handler = ${h.exportName};
    `;
    const wrapperPath = path.resolve(bundleDir, `${h.name}-entry.js`);
    fs.writeFileSync(wrapperPath, wrapperContent);

    await esbuild.build({
      entryPoints: [wrapperPath],
      bundle: true,
      platform: 'node',
      target: 'node20',
      format: 'cjs',
      outfile: outJs,
      sourcemap: true,
      external: [
        '@aws-sdk/*',
      ],
    });

    // Create zip
    await zipFile(outJs, outZip);
    console.log(`Created zip package: ${outZip}`);
  }

  console.log('Build complete.');
}

bundle().catch((err) => {
  console.error('Build failed:', err);
  process.exit(1);
});

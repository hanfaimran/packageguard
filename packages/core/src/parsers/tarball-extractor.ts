import zlib from 'node:zlib';
import tar from 'tar-stream';

export interface ExtractedFile {
  path: string;
  content: string;
  size: number;
}

export async function extractTarballInMemory(tarballBytes: Buffer): Promise<ExtractedFile[]> {
  return new Promise((resolve, reject) => {
    const files: ExtractedFile[] = [];

    let decompressed: Buffer;
    try {
      // npm tarballs are gzip-compressed (.tgz / .tar.gz)
      if (tarballBytes[0] === 0x1f && tarballBytes[1] === 0x8b) {
        decompressed = zlib.gunzipSync(tarballBytes);
      } else {
        decompressed = tarballBytes;
      }
    } catch (err) {
      return reject(new Error(`Failed to decompress tarball: ${(err as Error).message}`));
    }

    const extract = tar.extract();

    extract.on('entry', (header, stream, next) => {
      // Normalize path (strip root 'package/' prefix if present)
      let filePath = header.name;
      if (filePath.startsWith('package/')) {
        filePath = filePath.slice('package/'.length);
      }

      if (header.type === 'file') {
        const chunks: Buffer[] = [];
        stream.on('data', (chunk) => chunks.push(chunk));
        stream.on('end', () => {
          const contentBuf = Buffer.concat(chunks);
          // Only read text files into content string if reasonable size
          const content = contentBuf.toString('utf-8');
          files.push({
            path: filePath,
            content,
            size: header.size || contentBuf.length,
          });
          next();
        });
        stream.resume();
      } else {
        stream.resume();
        next();
      }
    });

    extract.on('finish', () => resolve(files));
    extract.on('error', (err) => reject(err));

    extract.end(decompressed);
  });
}

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { scanFromRegistry } from '@packageguard/core';
import { generateAllFixtures } from './fixtures/generator.js';
import { FakeRegistryServer } from './fake-registry.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main(): Promise<void> {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

  const fixtures = generateAllFixtures(privPem);
  const registryServer = new FakeRegistryServer({ port: 4002, fixtures });
  const registryUrl = await registryServer.start();
  console.log(`Fake registry listening on ${registryUrl}`);

  const fixtureList = Object.values(fixtures).map((f) => ({
    package: f.name,
    version: f.version,
  }));

  const htmlPath = path.resolve(__dirname, '../index.html');

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1:3000'}`);

    if (req.method === 'GET' && url.pathname === '/') {
      try {
        const htmlContent = fs.readFileSync(htmlPath, 'utf-8');
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(htmlContent);
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        return res.end(`Failed to load index.html: ${(err as Error).message}`);
      }
    }

    if (req.method === 'GET' && url.pathname === '/api/fixtures') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(fixtureList));
    }

    if (req.method === 'POST' && url.pathname === '/api/scan') {
      let body = '';
      let bodyLength = 0;
      let tooLarge = false;

      req.on('data', (chunk: Buffer) => {
        bodyLength += chunk.length;
        if (bodyLength > 32 * 1024) {
          tooLarge = true;
          req.destroy();
          return;
        }
        body += chunk.toString('utf-8');
      });

      req.on('error', () => {
        if (tooLarge) {
          if (!res.headersSent) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Payload exceeds 32 KB limit' }));
          }
        }
      });

      req.on('end', async () => {
        if (tooLarge) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Payload exceeds 32 KB limit' }));
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(body || '{}');
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Invalid JSON body' }));
        }

        if (
          !parsed ||
          typeof parsed !== 'object' ||
          !('package' in parsed) ||
          !('version' in parsed) ||
          typeof (parsed as { package: unknown }).package !== 'string' ||
          typeof (parsed as { version: unknown }).version !== 'string' ||
          !(parsed as { package: string }).package.trim() ||
          !(parsed as { version: string }).version.trim()
        ) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Missing package or version fields' }));
        }

        const { package: pkgName, version: pkgVer } = parsed as { package: string; version: string };

        try {
          const report = await scanFromRegistry(pkgName.trim(), pkgVer.trim(), {
            registryUrl,
            trustedPublicKeys: { 'packageguard-eval-key-1': pubPem },
          });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify(report));
        } catch (err) {
          const errMsg = (err as Error).message || String(err);
          if (
            errMsg.includes('not found') ||
            errMsg.includes('Tarball missing') ||
            errMsg.includes('404')
          ) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: errMsg }));
          }
          res.writeHead(500, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: errMsg }));
        }
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  });

  server.listen(3000, '127.0.0.1', () => {
    console.log('PackageGuard demo server running at http://127.0.0.1:3000');
  });

  const cleanup = async () => {
    console.log('\nShutting down demo server and fake registry...');
    server.close();
    await registryServer.stop();
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
}

main().catch((err) => {
  console.error('Failed to start demo server:', err);
  process.exit(1);
});

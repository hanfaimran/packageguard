import http from 'node:http';
import type { PreparedFixture } from './fixtures/generator.js';

export interface FakeRegistryOptions {
  port?: number;
  fixtures: Record<string, PreparedFixture>;
}

export class FakeRegistryServer {
  private server?: http.Server;
  private readonly port: number;
  private readonly fixtures: Record<string, PreparedFixture>;

  constructor(options: FakeRegistryOptions) {
    this.port = options.port || 4000;
    this.fixtures = options.fixtures;
  }

  async start(): Promise<string> {
    return new Promise((resolve) => {
      this.server = http.createServer((req, res) => {
        const url = new URL(req.url || '/', `http://127.0.0.1:${this.port}`);
        const pathname = decodeURIComponent(url.pathname);

        // Tarball endpoint: /:pkg/-/:pkg-:ver.tgz
        const tarballMatch = pathname.match(/^\/([^\/]+)\/-\/([^\/]+)-([^\/]+)\.tgz$/);
        if (tarballMatch) {
          const [, pkg, , ver] = tarballMatch;
          const key = `${pkg}@${ver}`;
          const fixture = this.fixtures[key];
          if (fixture) {
            res.writeHead(200, {
              'Content-Type': 'application/octet-stream',
              'Content-Length': fixture.tarballBytes.length,
            });
            return res.end(fixture.tarballBytes);
          }
          res.writeHead(404);
          return res.end('Tarball not found');
        }

        // Package document endpoint: /:pkg
        const pkgName = pathname.replace(/^\//, '');
        // Find document matching package name
        const matchingFixture = Object.values(this.fixtures).find((f) => f.name === pkgName);
        if (matchingFixture) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify(matchingFixture.packageDocument));
        }

        res.writeHead(404);
        res.end('Not found');
      });

      this.server.listen(this.port, '127.0.0.1', () => {
        resolve(`http://127.0.0.1:${this.port}`);
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.server) return resolve();
      this.server.close((err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  }
}

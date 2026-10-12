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

  /**
   * Build the merged package document for a given package name.
   * Combines all fixture versions into one npm-registry-compatible document:
   * - "versions" map contains ALL published versions
   * - "time" map has created/modified plus per-version timestamps (earlier versions earlier)
   * - "dist-tags.latest" points to the highest-versioned entry by semver
   * - Per-version "dist.tarball" URLs are rewritten to THIS server's address so they
   *   work regardless of which port the test server binds to.
   */
  private buildPackageDocument(
    pkgName: string,
    serverOrigin: string,
  ): Record<string, unknown> | null {
    // Collect all fixtures for this package name
    const matching = Object.values(this.fixtures).filter((f) => f.name === pkgName);
    if (matching.length === 0) return null;

    // Sort fixtures by semver so earlier versions come first
    matching.sort((a, b) => {
      const aParts = a.version.split('.').map(Number);
      const bParts = b.version.split('.').map(Number);
      for (let i = 0; i < 3; i++) {
        const diff = (aParts[i] ?? 0) - (bParts[i] ?? 0);
        if (diff !== 0) return diff;
      }
      return 0;
    });

    const latestFixture = matching[matching.length - 1];

    // Start from the latest fixture's packageDocument for top-level fields
    // (name, repository, description, etc.)
    const base = JSON.parse(
      JSON.stringify(latestFixture.packageDocument),
    ) as Record<string, unknown>;

    // Build merged versions and time from ALL fixture packageDocuments
    const mergedVersions: Record<string, unknown> = {};
    const mergedTime: Record<string, string> = {};

    for (const fixture of matching) {
      const doc = fixture.packageDocument as Record<string, unknown>;
      const docVersions = (doc.versions ?? {}) as Record<string, unknown>;

      for (const [v, versionEntry] of Object.entries(docVersions)) {
        // Deep-copy so we can rewrite dist.tarball safely
        const entry = JSON.parse(JSON.stringify(versionEntry)) as Record<string, unknown>;
        const dist = entry.dist as Record<string, unknown> | undefined;
        if (dist) {
          // Always point to THIS server's address, regardless of what was baked into the fixture
          dist.tarball = `${serverOrigin}/${pkgName}/-/${pkgName}-${v}.tgz`;
        }
        mergedVersions[v] = entry;
      }

      // Merge version-keyed time entries (skip created/modified — we'll set those ourselves)
      const docTime = (doc.time ?? {}) as Record<string, string>;
      for (const [k, t] of Object.entries(docTime)) {
        if (k !== 'created' && k !== 'modified') {
          mergedTime[k] = t;
        }
      }
    }

    // Guarantee every fixture's own version has a time entry so scanFromRegistry
    // can order them correctly to pick the previous version.
    // Use monotonically increasing timestamps spaced 1 day apart.
    const epoch = new Date('2022-01-01T00:00:00.000Z').getTime();
    for (let i = 0; i < matching.length; i++) {
      const v = matching[i].version;
      if (!mergedTime[v]) {
        mergedTime[v] = new Date(epoch + i * 86_400_000).toISOString();
      }
    }

    // Sort version times so the time map is deterministic
    const sortedVersionKeys = Object.keys(mergedTime).sort(
      (a, b) => new Date(mergedTime[a]).getTime() - new Date(mergedTime[b]).getTime(),
    );
    const firstTime = mergedTime[sortedVersionKeys[0]] ?? new Date(epoch).toISOString();

    const time: Record<string, string> = {
      created: firstTime,
      modified: new Date().toISOString(),
    };
    for (const k of sortedVersionKeys) {
      time[k] = mergedTime[k];
    }

    base.versions = mergedVersions;
    base.time = time;
    base['dist-tags'] = { latest: latestFixture.version };
    // Top-level maintainers from the latest release (already in base from latestFixture.packageDocument)

    return base;
  }

  async start(): Promise<string> {
    return new Promise((resolve) => {
      this.server = http.createServer((req, res) => {
        const url = new URL(req.url || '/', `http://127.0.0.1:${this.port}`);
        const pathname = decodeURIComponent(url.pathname);
        const serverOrigin = `http://127.0.0.1:${this.port}`;

        // Tarball endpoint: /:pkg/-/:pkg-:ver.tgz
        // Handles both plain packages and scoped packages (/@scope/pkg/-/pkg-ver.tgz)
        const tarballMatch = pathname.match(/^\/(.+)\/-\/[^/]+-([^/]+)\.tgz$/);
        if (tarballMatch) {
          const pkgName = tarballMatch[1]; // e.g. "lodash" or "@types/node"
          const ver = tarballMatch[2];
          const key = `${pkgName}@${ver}`;
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

        // Package document endpoint: /:pkg (or /@scope/pkg)
        const pkgName = pathname.replace(/^\//, '');
        const doc = this.buildPackageDocument(pkgName, serverOrigin);
        if (doc) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify(doc));
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

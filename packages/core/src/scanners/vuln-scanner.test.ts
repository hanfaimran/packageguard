import { describe, it, expect, vi, beforeEach } from 'vitest';
import { parsePackageLock } from '../parsers/lockfile-parser.js';
import { OsvClient, normalizeOsvSeverity, cvssScoreToSeverity } from '../clients/osv-client.js';
import { VulnScanner } from './vuln-scanner.js';
import type { ScanContext } from '../types.js';

describe('LockfileParser, OsvClient & VulnScanner', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe('LockfileParser', () => {
    it('parses npm v2/v3 lockfile packages object', () => {
      const lockJson = JSON.stringify({
        name: 'my-project',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
          '': { name: 'my-project', version: '1.0.0' },
          'node_modules/lodash': {
            version: '4.17.21',
            resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
            integrity: 'sha512-xxx',
          },
          'node_modules/@scope/pkg': {
            version: '1.2.0',
            dev: true,
          },
        },
      });

      const parsed = parsePackageLock(lockJson);
      expect(parsed.length).toBe(2);
      expect(parsed[0].name).toBe('lodash');
      expect(parsed[0].version).toBe('4.17.21');
      expect(parsed[1].name).toBe('@scope/pkg');
      expect(parsed[1].dev).toBe(true);
    });

    it('parses npm v1 lockfile dependencies object', () => {
      const lockJson = JSON.stringify({
        name: 'my-project',
        dependencies: {
          ms: {
            version: '2.1.2',
            dependencies: {
              subms: { version: '1.0.0' },
            },
          },
        },
      });

      const parsed = parsePackageLock(lockJson);
      expect(parsed.length).toBe(2);
      expect(parsed[0].name).toBe('ms');
      expect(parsed[1].name).toBe('subms');
    });

    it('throws on invalid json', () => {
      expect(() => parsePackageLock('invalid json')).toThrow('Failed to parse package-lock.json');
    });
  });

  describe('OsvClient and Severity Normalization', () => {
    it('normalizes cvssScore to severity accurately', () => {
      expect(cvssScoreToSeverity(9.8)).toBe('CRITICAL');
      expect(cvssScoreToSeverity(7.5)).toBe('HIGH');
      expect(cvssScoreToSeverity(5.3)).toBe('MEDIUM');
      expect(cvssScoreToSeverity(2.1)).toBe('LOW');
      expect(cvssScoreToSeverity(0)).toBe('INFO');
    });

    it('normalizes various OSV response severity structures', () => {
      expect(
        normalizeOsvSeverity({
          id: 'GHSA-1',
          database_specific: { severity: 'HIGH' },
        }),
      ).toBe('HIGH');

      expect(
        normalizeOsvSeverity({
          id: 'GHSA-2',
          database_specific: { cvss: { score: 9.1 } },
        }),
      ).toBe('CRITICAL');

      expect(
        normalizeOsvSeverity({
          id: 'GHSA-3',
          severity: [{ type: 'CVSS_V3', score: '8.2' }],
        }),
      ).toBe('HIGH');

      expect(
        normalizeOsvSeverity({
          id: 'GHSA-4',
        }),
      ).toBe('MEDIUM');
    });

    it('OsvClient makes POST requests to query and querybatch', async () => {
      globalThis.fetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ vulns: [{ id: 'GHSA-test', summary: 'Prototype Pollution' }] }),
        } as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ results: [{ vulns: [{ id: 'GHSA-batch' }] }] }),
        } as any);

      const client = new OsvClient('https://api.osv.dev/v1');
      const vulns = await client.queryPackage('lodash', '4.17.20');
      expect(vulns.length).toBe(1);
      expect(vulns[0].id).toBe('GHSA-test');

      const batch = await client.queryBatch([{ package: { name: 'ms', ecosystem: 'npm' } }]);
      expect(batch.results.length).toBe(1);
    });

    it('OsvClient throws on HTTP error', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Error',
      } as any);

      const client = new OsvClient();
      await expect(client.queryPackage('pkg', '1.0.0')).rejects.toThrow('OSV API query failed');
      await expect(client.queryBatch([])).rejects.toThrow('OSV API batch query failed');
    });
  });

  describe('VulnScanner', () => {
    it('scans direct package vulnerabilities and lockfile transitive vulnerabilities', async () => {
      const mockOsvClient = {
        queryPackage: vi.fn().mockResolvedValue([
          {
            id: 'GHSA-direct',
            summary: 'SQL injection',
            database_specific: { severity: 'CRITICAL' },
          },
        ]),
        queryBatch: vi.fn().mockResolvedValue({
          results: [
            {
              vulns: [
                {
                  id: 'GHSA-transitive',
                  summary: 'ReDoS in transitive dep',
                  database_specific: { severity: 'HIGH' },
                },
              ],
            },
          ],
        }),
      } as unknown as OsvClient;

      const scanner = new VulnScanner(mockOsvClient);
      const ctx: ScanContext = {
        packageName: 'target-pkg',
        ecosystem: 'npm',
        version: '1.0.0',
        lockfileContent: JSON.stringify({
          packages: {
            '': { name: 'target-pkg', version: '1.0.0' },
            'node_modules/sub-pkg': { version: '0.1.0' },
          },
        }),
      };

      const evidence = await scanner.collect(ctx);
      expect(evidence.length).toBe(2);

      const direct = evidence.find((e) => e.dedupKey === 'vuln:target-pkg:GHSA-direct');
      expect(direct).toBeDefined();
      expect(direct?.severity).toBe('CRITICAL');

      const transitive = evidence.find((e) => e.dedupKey === 'vuln:sub-pkg:GHSA-transitive');
      expect(transitive).toBeDefined();
      expect(transitive?.severity).toBe('HIGH');
    });

    it('handles query failures gracefully without crashing scanner', async () => {
      const mockOsvClient = {
        queryPackage: vi.fn().mockRejectedValue(new Error('Network failure')),
        queryBatch: vi.fn(),
      } as unknown as OsvClient;

      const scanner = new VulnScanner(mockOsvClient);
      const ctx: ScanContext = {
        packageName: 'failing-pkg',
        ecosystem: 'npm',
        version: '1.0.0',
        lockfileContent: 'invalid-lockfile-json',
      };

      const evidence = await scanner.collect(ctx);
      expect(evidence.length).toBe(2);
      expect(evidence[0].dedupKey).toBe('vuln:query-error:failing-pkg');
      expect(evidence[1].dedupKey).toBe('vuln:lockfile:error');
    });
  });
});

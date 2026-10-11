import type { Scanner, ScanContext, Evidence } from '../types.js';
import { OsvClient, normalizeOsvSeverity } from '../clients/osv-client.js';
import { parsePackageLock } from '../parsers/lockfile-parser.js';

export class VulnScanner implements Scanner {
  readonly name = 'VulnScanner';

  constructor(private readonly osvClient: OsvClient = new OsvClient()) {}

  async collect(ctx: ScanContext): Promise<Evidence[]> {
    const evidence: Evidence[] = [];

    // 1. Direct package vulnerability query
    try {
      const directVulns = await this.osvClient.queryPackage(ctx.packageName, ctx.version, ctx.ecosystem);
      for (const vuln of directVulns) {
        const severity = normalizeOsvSeverity(vuln);
        evidence.push({
          id: `vuln-direct-${vuln.id}`,
          scanner: this.name,
          category: 'vulnerability',
          severity,
          confidence: 0.95,
          description: `Known vulnerability in ${ctx.packageName}@${ctx.version}: ${vuln.id} - ${vuln.summary || vuln.details || 'No details'}`,
          dedupKey: `vuln:${ctx.packageName}:${vuln.id}`,
          rawData: {
            vulnId: vuln.id,
            aliases: vuln.aliases,
            severity,
            direct: true,
          },
        });
      }
    } catch (err) {
      // Best-effort network scanning
      evidence.push({
        id: `vuln-query-error-${ctx.packageName}`,
        scanner: this.name,
        category: 'vulnerability',
        severity: 'INFO',
        confidence: 0.5,
        description: `Failed to query OSV for direct package: ${(err as Error).message}`,
        dedupKey: `vuln:query-error:${ctx.packageName}`,
      });
    }

    // 2. Transitive dependencies from lockfile if provided
    if (ctx.lockfileContent) {
      try {
        const lockPkgs = parsePackageLock(ctx.lockfileContent);
        // Exclude root package itself
        const transitive = lockPkgs.filter((p) => p.name !== ctx.packageName);

        if (transitive.length > 0) {
          const queries = transitive.map((p) => ({
            package: { name: p.name, ecosystem: 'npm' },
            version: p.version,
          }));

          // Batch in chunks of 500 if needed, but here simple querybatch
          const batchRes = await this.osvClient.queryBatch(queries);
          batchRes.results.forEach((res, idx) => {
            if (res.vulns && res.vulns.length > 0) {
              const targetDep = transitive[idx];
              for (const vuln of res.vulns) {
                const severity = normalizeOsvSeverity(vuln);
                evidence.push({
                  id: `vuln-transitive-${targetDep.name}-${vuln.id}`,
                  scanner: this.name,
                  category: 'vulnerability',
                  severity,
                  confidence: 0.9,
                  description: `Transitive vulnerability via ${targetDep.name}@${targetDep.version}: ${vuln.id} - ${vuln.summary || 'Known flaw'}`,
                  dedupKey: `vuln:${targetDep.name}:${vuln.id}`,
                  rawData: {
                    vulnId: vuln.id,
                    transitiveDep: targetDep.name,
                    version: targetDep.version,
                    severity,
                    direct: false,
                  },
                });
              }
            }
          });
        }
      } catch (err) {
        evidence.push({
          id: 'vuln-lockfile-error',
          scanner: this.name,
          category: 'vulnerability',
          severity: 'INFO',
          confidence: 0.5,
          description: `Failed to inspect transitive lockfile dependencies: ${(err as Error).message}`,
          dedupKey: 'vuln:lockfile:error',
        });
      }
    }

    return evidence;
  }
}

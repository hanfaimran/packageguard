import { RegistryClient } from './clients/registry-client.js';
export const PACKAGEGUARD_VERSION = '0.1.0';

export function createEmptyEvidence(id: string, scanner: string): import('./types.js').Evidence {
  return {
    id,
    scanner,
    category: 'metadata',
    severity: 'INFO',
    confidence: 1.0,
    description: '',
    dedupKey: `${scanner}:${id}`,
  };
}

export * from './types.js';
export * from './clients/registry-client.js';
export * from './clients/osv-client.js';
export * from './parsers/lockfile-parser.js';
export * from './parsers/tarball-extractor.js';
export * from './scanners/metadata-scanner.js';
export * from './scanners/vuln-scanner.js';
export * from './scanners/integrity-scanner.js';
export * from './scanners/typosquat-scanner.js';
export * from './scanners/static-analyzer.js';
export * from './scanners/version-diff-scanner.js';
export * from './engine/deduplicator.js';
export * from './engine/risk-engine.js';
export * from './engine/policy-engine.js';
export * from './renderers/report-renderer.js';

import type { ScanContext, Report } from './types.js';
import { MetadataScanner } from './scanners/metadata-scanner.js';
import { VulnScanner } from './scanners/vuln-scanner.js';
import { IntegrityScanner } from './scanners/integrity-scanner.js';
import { TyposquatScanner } from './scanners/typosquat-scanner.js';
import { StaticAnalyzer } from './scanners/static-analyzer.js';
import { VersionDiffScanner } from './scanners/version-diff-scanner.js';
import { deduplicateEvidence } from './engine/deduplicator.js';
import { RiskEngine } from './engine/risk-engine.js';
import { PolicyEngine } from './engine/policy-engine.js';

export interface ScanOptions {
  trustedPublicKeys?: Record<string, string>;
  osvClient?: import('./clients/osv-client.js').OsvClient;
  policy?: import('./engine/policy-engine.js').GuardPolicy;
}

export async function scanPackage(ctx: ScanContext, options: ScanOptions = {}): Promise<Report> {
  const metadataScanner = new MetadataScanner();
  const vulnScanner = new VulnScanner(options.osvClient);
  const integrityScanner = new IntegrityScanner(options.trustedPublicKeys || {});
  const typosquatScanner = new TyposquatScanner();
  const staticAnalyzer = new StaticAnalyzer();
  const versionDiffScanner = new VersionDiffScanner(staticAnalyzer);

  // 1. Run IntegrityScanner to establish cryptographic verificationStatus
  const integrityRes = await integrityScanner.verify(ctx);

  // 2. Run all scanners in parallel to collect structured evidence
  const [metaEv, vulnEv, typoEv, staticEv, diffEv] = await Promise.all([
    metadataScanner.collect(ctx),
    vulnScanner.collect(ctx),
    typosquatScanner.collect(ctx),
    staticAnalyzer.collect(ctx),
    versionDiffScanner.collect(ctx),
  ]);

  const rawEvidence = [
    ...integrityRes.evidence,
    ...metaEv,
    ...vulnEv,
    ...typoEv,
    ...staticEv,
    ...diffEv,
  ];

  // 3. Deduplicate evidence
  const dedupedEvidence = deduplicateEvidence(rawEvidence);

  // 4. Policy Pre-check / Hard blocks
  const policyEngine = new PolicyEngine(options.policy || {});
  // Initial tentative risk calculation
  const riskEngine = new RiskEngine();
  const tentativeReport = riskEngine.evaluate(
    ctx.packageName,
    ctx.version,
    dedupedEvidence,
    integrityRes.status,
  );

  const policyRes = policyEngine.evaluate(
    ctx.packageName,
    ctx.version,
    tentativeReport.riskScore,
    integrityRes.status,
    dedupedEvidence,
  );

  // 5. Final Report Evaluation with policy hard blocks
  const finalReport = riskEngine.evaluate(
    ctx.packageName,
    ctx.version,
    dedupedEvidence,
    integrityRes.status,
    policyRes.hardBlocks,
  );

  if (options.policy) {
    finalReport.policyApplied = {
      name: options.policy.name,
      passed: policyRes.passed,
      violations: policyRes.violations,
    };
  }

  return finalReport;
}

export interface ScanFromRegistryOptions {
  registryUrl?: string;
  trustedPublicKeys?: Record<string, string>;
  osvClient?: import('./clients/osv-client.js').OsvClient;
  policy?: import('./engine/policy-engine.js').GuardPolicy;
}

export async function scanFromRegistry(
  packageName: string,
  version: string,
  options: ScanFromRegistryOptions = {},
): Promise<Report> {
  const registryUrl = options.registryUrl || 'https://registry.npmjs.org';
  const client = new RegistryClient(registryUrl);

  // 1. Fetch package metadata
  const doc = await client.getPackageDocument(packageName);
  const targetVersionDoc = doc.versions?.[version];
  if (!targetVersionDoc) {
    throw new Error(`Version ${version} of package ${packageName} not found in registry`);
  }

  /**
   * Rewrite a tarball URL to use the configured registry origin.
   * The registry document may contain URLs baked in at fixture-generation time
   * pointing to a different host/port. For a custom registryUrl we always rewrite
   * the host+port so tarballs are fetched from the correct server.
   */
  function rewriteTarballUrl(tarball: string): string {
    if (!options.registryUrl) return tarball;
    try {
      const configured = new URL(options.registryUrl.replace(/\/$/, ''));
      const embedded = new URL(tarball);
      if (embedded.origin !== configured.origin) {
        embedded.host = configured.host;
        embedded.protocol = configured.protocol;
        return embedded.toString();
      }
    } catch {
      // If parsing fails, return the original URL unchanged
    }
    return tarball;
  }

  // 2. Resolve tarball URL and download target version tarball
  let tarballUrl = targetVersionDoc.dist?.tarball;
  if (!tarballUrl) {
    throw new Error(`Tarball URL missing for ${packageName}@${version} in registry document`);
  }
  tarballUrl = rewriteTarballUrl(tarballUrl);

  const tarballBytes = await client.downloadTarball(tarballUrl);

  // 3. Find previous version by publish time (if available in doc.time)
  let previousVersion: string | undefined;
  if (doc.time) {
    const targetPublishTime = doc.time[version] ? new Date(doc.time[version]).getTime() : Infinity;
    // Collect earlier published versions
    const earlierVersions: Array<{ version: string; time: number }> = [];
    for (const [v, timeStr] of Object.entries(doc.time)) {
      if (['created', 'modified'].includes(v)) continue;
      if (v === version) continue;
      if (doc.versions?.[v]) {
        const t = new Date(timeStr as string).getTime();
        if (t <= targetPublishTime) {
          earlierVersions.push({ version: v, time: t });
        }
      }
    }
    earlierVersions.sort((a, b) => b.time - a.time);
    if (earlierVersions.length > 0) {
      previousVersion = earlierVersions[0].version;
    }
  }

  let previousVersionTarballBytes: Buffer | undefined;
  let previousVersionMetadata: Record<string, unknown> | undefined;

  if (previousVersion && doc.versions?.[previousVersion]) {
    const prevDoc = doc.versions[previousVersion];
    let prevTarballUrl = prevDoc.dist?.tarball;
    if (prevTarballUrl) {
      prevTarballUrl = rewriteTarballUrl(prevTarballUrl);
      try {
        previousVersionTarballBytes = await client.downloadTarball(prevTarballUrl);
        previousVersionMetadata = {
          name: packageName,
          maintainers: prevDoc.maintainers || doc.maintainers,
          versions: {
            [previousVersion]: prevDoc,
          },
        };
      } catch {
        // If previous version download fails, skip diff gracefully
        previousVersionTarballBytes = undefined;
        previousVersionMetadata = undefined;
      }
    }
  }

  const scanCtx: ScanContext = {
    packageName,
    ecosystem: 'npm',
    version,
    registryUrl,
    tarballBytes,
    registryMetadata: doc as unknown as Record<string, unknown>,
    previousVersionTarballBytes,
    previousVersionMetadata,
  };

  return scanPackage(scanCtx, {
    trustedPublicKeys: options.trustedPublicKeys,
    osvClient: options.osvClient,
    policy: options.policy,
  });
}


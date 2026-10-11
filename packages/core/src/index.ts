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

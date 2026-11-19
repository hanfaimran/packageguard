import type { Report, Verdict } from '../types.js';
import { parsePackageLock } from '../parsers/lockfile-parser.js';

export const MAX_DEPENDENCIES = 25;
const DEFAULT_CONCURRENCY = 5;
const PLAIN_VERSION = /^\d+\.\d+\.\d+/;

export type DependencyStatus = Verdict | 'Error';

export interface RepoScanItem {
  name: string;
  version: string;
  status: DependencyStatus;
  riskScore?: number;
  error?: string;
}

export interface RepoScanResult {
  repo: string;
  overallVerdict: Verdict;
  totalDependencies: number;
  scanned: number;
  skipped: number;
  counts: Record<DependencyStatus, number>;
  items: RepoScanItem[];
}

export interface ScanRepoOptions {
  repoLabel: string;
  scanDependency: (name: string, version: string) => Promise<Report>;
  maxDependencies?: number;
  concurrency?: number;
}

const STATUS_ORDER: Record<DependencyStatus, number> = { Block: 0, Review: 1, Error: 2, Safe: 3 };

/**
 * Scan the production dependencies listed in a package-lock.json.
 * The scan function is passed in so this code stays testable and never
 * depends on the network directly.
 */
export async function scanRepoDependencies(
  lockfileText: string,
  options: ScanRepoOptions,
): Promise<RepoScanResult> {
  const max = options.maxDependencies ?? MAX_DEPENDENCIES;
  const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;

  const seen = new Set<string>();
  const deps = parsePackageLock(lockfileText).filter((d) => {
    if (d.dev || !PLAIN_VERSION.test(d.version)) return false;
    const key = `${d.name}@${d.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const toScan = deps.slice(0, max);
  const items: RepoScanItem[] = new Array(toScan.length);
  let next = 0;

  async function worker(): Promise<void> {
    while (next < toScan.length) {
      const index = next++;
      const dep = toScan[index];
      try {
        const report = await options.scanDependency(dep.name, dep.version);
        items[index] = {
          name: dep.name,
          version: dep.version,
          status: report.verdict,
          riskScore: report.riskScore,
        };
      } catch (err) {
        items[index] = {
          name: dep.name,
          version: dep.version,
          status: 'Error',
          error: (err as Error).message,
        };
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, toScan.length) }, () => worker()));

  const counts: Record<DependencyStatus, number> = { Safe: 0, Review: 0, Block: 0, Error: 0 };
  for (const item of items) counts[item.status]++;

  const overallVerdict: Verdict =
    counts.Block > 0 ? 'Block' : counts.Review > 0 || counts.Error > 0 ? 'Review' : 'Safe';

  items.sort(
    (a, b) =>
      STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || (a.riskScore ?? 0) - (b.riskScore ?? 0),
  );

  return {
    repo: options.repoLabel,
    overallVerdict,
    totalDependencies: deps.length,
    scanned: toScan.length,
    skipped: deps.length - toScan.length,
    counts,
    items,
  };
}

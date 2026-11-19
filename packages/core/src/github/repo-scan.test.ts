import { describe, it, expect } from 'vitest';
import type { Report } from '../types.js';
import { scanRepoDependencies } from './repo-scan.js';

const lockfile = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': {},
    'node_modules/a': { version: '1.0.0' },
    'node_modules/b': { version: '2.0.0' },
    'node_modules/c': { version: '3.0.0', dev: true },
    'node_modules/d': { version: '4.0.0' },
  },
});

function report(verdict: string, riskScore: number): Report {
  return { verdict, riskScore } as unknown as Report;
}

describe('scanRepoDependencies', () => {
  it('skips dev dependencies, counts verdicts and blocks when one dependency blocks', async () => {
    const result = await scanRepoDependencies(lockfile, {
      repoLabel: 'o/r',
      scanDependency: async (name) => (name === 'b' ? report('Block', 10) : report('Safe', 90)),
    });
    expect(result.totalDependencies).toBe(3);
    expect(result.counts).toEqual({ Safe: 2, Review: 0, Block: 1, Error: 0 });
    expect(result.overallVerdict).toBe('Block');
    expect(result.items[0].name).toBe('b');
  });

  it('treats a failed scan as Review, not Safe', async () => {
    const result = await scanRepoDependencies(lockfile, {
      repoLabel: 'o/r',
      scanDependency: async (name) => {
        if (name === 'd') throw new Error('registry down');
        return report('Safe', 90);
      },
    });
    expect(result.counts.Error).toBe(1);
    expect(result.overallVerdict).toBe('Review');
    expect(result.items.find((i) => i.name === 'd')?.error).toBe('registry down');
  });

  it('respects the dependency cap and reports skipped ones', async () => {
    const result = await scanRepoDependencies(lockfile, {
      repoLabel: 'o/r',
      maxDependencies: 1,
      scanDependency: async () => report('Safe', 90),
    });
    expect(result.scanned).toBe(1);
    expect(result.skipped).toBe(2);
    expect(result.overallVerdict).toBe('Safe');
  });
});
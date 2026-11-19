import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { APIGatewayProxyEvent } from 'aws-lambda';

vi.mock('@packageguard/core', async () => {
  const actual = await vi.importActual<typeof import('@packageguard/core')>('@packageguard/core');
  return { ...actual, fetchRepoLockfile: vi.fn(), scanFromRegistry: vi.fn() };
});

import { fetchRepoLockfile, scanFromRegistry, type Report } from '@packageguard/core';
import { postScanRepoHandler, HOSTED_MAX_DEPENDENCIES } from './repo-scan-handler.js';

const mockFetchLockfile = vi.mocked(fetchRepoLockfile);
const mockScan = vi.mocked(scanFromRegistry);

function event(body: unknown): APIGatewayProxyEvent {
  return { body: body === null ? null : JSON.stringify(body) } as unknown as APIGatewayProxyEvent;
}

function lockfileWith(count: number): string {
  const packages: Record<string, { version: string }> = { '': { version: '0.0.0' } };
  for (let i = 0; i < count; i++) {
    packages[`node_modules/pkg${i}`] = { version: '1.0.0' };
  }
  return JSON.stringify({ lockfileVersion: 3, packages });
}

describe('postScanRepoHandler', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockScan.mockResolvedValue({ verdict: 'Safe', riskScore: 90 } as unknown as Report);
  });

  it('rejects a missing repoUrl', async () => {
    const res = await postScanRepoHandler(event({}));
    expect(res.statusCode).toBe(400);
  });

  it('rejects non-GitHub URLs without fetching anything', async () => {
    const res = await postScanRepoHandler(event({ repoUrl: 'https://evil.com/a/b' }));
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/github\.com/);
    expect(mockFetchLockfile).not.toHaveBeenCalled();
  });

  it('returns the combined result for a repo', async () => {
    mockFetchLockfile.mockResolvedValue(lockfileWith(2));
    const res = await postScanRepoHandler(event({ repoUrl: 'https://github.com/o/r' }));
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.repo).toBe('o/r');
    expect(body.counts.Safe).toBe(2);
    expect(body.overallVerdict).toBe('Safe');
  });

  it('caps the number of dependencies scanned', async () => {
    mockFetchLockfile.mockResolvedValue(lockfileWith(HOSTED_MAX_DEPENDENCIES + 2));
    const res = await postScanRepoHandler(event({ repoUrl: 'https://github.com/o/r' }));
    const body = JSON.parse(res.body);
    expect(body.scanned).toBe(HOSTED_MAX_DEPENDENCIES);
    expect(body.skipped).toBe(2);
  });

  it('returns a clear error when the repo has no lockfile', async () => {
    mockFetchLockfile.mockRejectedValue(new Error('No package-lock.json found in this repository.'));
    const res = await postScanRepoHandler(event({ repoUrl: 'https://github.com/o/r' }));
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/package-lock\.json/);
  });
});
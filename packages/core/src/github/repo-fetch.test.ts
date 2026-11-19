import { describe, it, expect } from 'vitest';
import { fetchRepoLockfile, MAX_LOCKFILE_BYTES } from './repo-fetch.js';

function fakeFetch(status: number, body = '', onCall?: (url: string) => void): typeof fetch {
  return (async (input: unknown) => {
    onCall?.(String(input));
    return new Response(body, { status });
  }) as unknown as typeof fetch;
}

const ref = { owner: 'a', repo: 'b' };

describe('fetchRepoLockfile', () => {
  it('returns the lockfile text and only calls api.github.com', async () => {
    let calledUrl = '';
    const text = await fetchRepoLockfile(ref, {
      fetchImpl: fakeFetch(200, '{"lockfileVersion":3}', (u) => (calledUrl = u)),
    });
    expect(text).toBe('{"lockfileVersion":3}');
    expect(calledUrl).toBe('https://api.github.com/repos/a/b/contents/package-lock.json');
  });

  it('explains a missing lockfile', async () => {
    await expect(fetchRepoLockfile(ref, { fetchImpl: fakeFetch(404) })).rejects.toThrow(/package-lock\.json/);
  });

  it('reports rate limiting', async () => {
    await expect(fetchRepoLockfile(ref, { fetchImpl: fakeFetch(403) })).rejects.toThrow(/rate limit/i);
  });

  it('rejects oversized lockfiles', async () => {
    const big = 'x'.repeat(MAX_LOCKFILE_BYTES + 1);
    await expect(fetchRepoLockfile(ref, { fetchImpl: fakeFetch(200, big) })).rejects.toThrow(/2 MB/);
  });
});
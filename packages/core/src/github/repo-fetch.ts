import type { GithubRepoRef } from './repo-url.js';

export const MAX_LOCKFILE_BYTES = 2 * 1024 * 1024;

export interface FetchRepoLockfileOptions {
  fetchImpl?: typeof fetch;
  token?: string;
}

export async function fetchRepoLockfile(
  ref: GithubRepoRef,
  options: FetchRepoLockfileOptions = {},
): Promise<string> {
  const doFetch = options.fetchImpl ?? fetch;
  const url = `https://api.github.com/repos/${encodeURIComponent(ref.owner)}/${encodeURIComponent(ref.repo)}/contents/package-lock.json`;

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.raw+json',
    'User-Agent': 'PackageGuard',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (options.token) {
    headers.Authorization = `Bearer ${options.token}`;
  }

  const res = await doFetch(url, { headers });

  if (res.status === 404) {
    throw new Error(
      'No package-lock.json found in this repository. Only public npm projects with a lockfile are supported.',
    );
  }
  if (res.status === 403 || res.status === 429) {
    throw new Error('GitHub rate limit reached. Try again later.');
  }
  if (!res.ok) {
    throw new Error(`GitHub returned an unexpected response (${res.status})`);
  }

  const declaredLength = Number(res.headers.get('content-length') ?? 0);
  if (declaredLength > MAX_LOCKFILE_BYTES) {
    throw new Error('package-lock.json is larger than the 2 MB limit');
  }

  const text = await res.text();
  if (Buffer.byteLength(text, 'utf8') > MAX_LOCKFILE_BYTES) {
    throw new Error('package-lock.json is larger than the 2 MB limit');
  }
  return text;
}
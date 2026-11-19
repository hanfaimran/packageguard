export interface GithubRepoRef {
  owner: string;
  repo: string;
}

const GITHUB_HOSTS = new Set(['github.com', 'www.github.com']);
const NAME_REGEX = /^[A-Za-z0-9_.-]{1,100}$/;

export function parseGithubRepoUrl(input: string): GithubRepoRef {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new Error('Enter a full GitHub URL, e.g. https://github.com/owner/repo');
  }

  if (
    url.protocol !== 'https:' ||
    !GITHUB_HOSTS.has(url.hostname) ||
    url.username ||
    url.password
  ) {
    throw new Error('Only https://github.com URLs are supported');
  }

  const [owner, rawRepo] = url.pathname.split('/').filter(Boolean);
  const repo = rawRepo ? rawRepo.replace(/\.git$/, '') : '';

  if (!owner || !repo || !NAME_REGEX.test(owner) || !NAME_REGEX.test(repo)) {
    throw new Error('URL must look like https://github.com/owner/repo');
  }

  return { owner, repo };
}

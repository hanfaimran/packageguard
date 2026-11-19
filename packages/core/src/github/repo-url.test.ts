import { describe, it, expect } from 'vitest';
import { parseGithubRepoUrl } from './repo-url.js';

describe('parseGithubRepoUrl', () => {
  it('parses a normal repo URL', () => {
    expect(parseGithubRepoUrl('https://github.com/hanfaimran/packageguard')).toEqual({
      owner: 'hanfaimran',
      repo: 'packageguard',
    });
  });

  it('handles .git suffix, trailing slash and extra path', () => {
    expect(parseGithubRepoUrl('https://github.com/a/b.git')).toEqual({ owner: 'a', repo: 'b' });
    expect(parseGithubRepoUrl('https://github.com/a/b/')).toEqual({ owner: 'a', repo: 'b' });
    expect(parseGithubRepoUrl('https://github.com/a/b/tree/main/src')).toEqual({ owner: 'a', repo: 'b' });
  });

  it('rejects other hosts, http and embedded credentials', () => {
    expect(() => parseGithubRepoUrl('https://evil.com/a/b')).toThrow();
    expect(() => parseGithubRepoUrl('http://github.com/a/b')).toThrow();
    expect(() => parseGithubRepoUrl('https://user:pw@github.com/a/b')).toThrow();
    expect(() => parseGithubRepoUrl('https://github.com.evil.com/a/b')).toThrow();
  });

  it('rejects incomplete or invalid URLs', () => {
    expect(() => parseGithubRepoUrl('not a url')).toThrow();
    expect(() => parseGithubRepoUrl('https://github.com/onlyowner')).toThrow();
    expect(() => parseGithubRepoUrl('https://github.com/a/b c')).toThrow();
  });
});
export interface LockfilePackageInfo {
  name: string;
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
}

export function parsePackageLock(lockfileContent: string): LockfilePackageInfo[] {
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(lockfileContent);
  } catch (err) {
    throw new Error(`Failed to parse package-lock.json: ${(err as Error).message}`);
  }

  const results: LockfilePackageInfo[] = [];

  // npm v2/v3 lockfile has `packages` object
  if (json.packages && typeof json.packages === 'object') {
    const pkgs = json.packages as Record<string, Record<string, unknown>>;
    for (const [key, val] of Object.entries(pkgs)) {
      if (!key) continue; // root project is ""
      const version = typeof val.version === 'string' ? val.version : '';
      if (!version) continue;

      let name = '';
      if (typeof val.name === 'string') {
        name = val.name;
      } else {
        const parts = key.split('node_modules/');
        name = parts[parts.length - 1];
      }

      if (name && version) {
        results.push({
          name,
          version,
          resolved: typeof val.resolved === 'string' ? val.resolved : undefined,
          integrity: typeof val.integrity === 'string' ? val.integrity : undefined,
          dev: Boolean(val.dev),
        });
      }
    }
  } else if (json.dependencies && typeof json.dependencies === 'object') {
    // npm v1 format
    function recurseDeps(deps: Record<string, Record<string, unknown>>) {
      for (const [name, val] of Object.entries(deps)) {
        const version = typeof val.version === 'string' ? val.version : '';
        if (version) {
          results.push({
            name,
            version,
            resolved: typeof val.resolved === 'string' ? val.resolved : undefined,
            integrity: typeof val.integrity === 'string' ? val.integrity : undefined,
            dev: Boolean(val.dev),
          });
        }
        if (val.dependencies && typeof val.dependencies === 'object') {
          recurseDeps(val.dependencies as Record<string, Record<string, unknown>>);
        }
      }
    }
    recurseDeps(json.dependencies as Record<string, Record<string, unknown>>);
  }

  return results;
}

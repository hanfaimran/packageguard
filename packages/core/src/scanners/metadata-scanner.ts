import type { Scanner, ScanContext, Evidence } from '../types.js';
import type { RegistryPackageDocument, RegistryPackageVersion } from '../clients/registry-client.js';

export class MetadataScanner implements Scanner {
  readonly name = 'MetadataScanner';

  async collect(ctx: ScanContext): Promise<Evidence[]> {
    const evidence: Evidence[] = [];
    const meta = ctx.registryMetadata as RegistryPackageDocument | undefined;
    if (!meta) {
      return evidence;
    }

    const versionDoc: RegistryPackageVersion | undefined =
      meta.versions?.[ctx.version] || (meta as unknown as RegistryPackageVersion);

    // 1. Package age check (< 30 days)
    if (meta.time) {
      const createdStr = meta.time.created;
      const releaseStr = meta.time[ctx.version] || createdStr;
      if (releaseStr) {
        const releaseDate = new Date(releaseStr);
        const now = new Date();
        const ageInDays = (now.getTime() - releaseDate.getTime()) / (1000 * 60 * 60 * 24);
        if (ageInDays < 30) {
          evidence.push({
            id: `meta-age-${ctx.version}`,
            scanner: this.name,
            category: 'metadata',
            severity: 'LOW',
            confidence: 0.8,
            description: `Package version was released ${Math.max(0, Math.round(ageInDays))} days ago (< 30 days threshold)`,
            dedupKey: `metadata:age:${ctx.packageName}`,
            rawData: { ageInDays: Math.round(ageInDays), releaseStr },
          });
        }
      }
    }

    // 2. Missing repository link
    const repo = versionDoc?.repository || meta.repository;
    const hasRepo =
      (typeof repo === 'string' && repo.trim().length > 0) ||
      (typeof repo === 'object' && repo !== null && Boolean(repo.url));
    if (!hasRepo) {
      evidence.push({
        id: 'meta-missing-repo',
        scanner: this.name,
        category: 'metadata',
        severity: 'LOW',
        confidence: 0.7,
        description: 'Package has no linked source code repository',
        dedupKey: `metadata:repo:missing:${ctx.packageName}`,
      });
    }

    // 3. Install scripts present
    if (versionDoc?.scripts) {
      const installScripts = ['preinstall', 'install', 'postinstall', 'prepublish', 'prepare'];
      for (const scriptKey of installScripts) {
        if (versionDoc.scripts[scriptKey]) {
          evidence.push({
            id: `meta-install-script-${scriptKey}`,
            scanner: this.name,
            category: 'metadata',
            severity: 'MEDIUM',
            confidence: 0.9,
            description: `Lifecycle install script detected: '${scriptKey}': "${versionDoc.scripts[scriptKey]}"`,
            dedupKey: `lifecycle:script:${scriptKey}`,
            rawData: {
              script: scriptKey,
              command: versionDoc.scripts[scriptKey],
            },
          });
        }
      }
    }

    // 4. Maintainer count check (few maintainers <= 1)
    const maintainers = versionDoc?.maintainers || meta.maintainers || [];
    if (maintainers.length <= 1) {
      evidence.push({
        id: 'meta-few-maintainers',
        scanner: this.name,
        category: 'metadata',
        severity: 'LOW',
        confidence: 0.6,
        description: `Package has single maintainer (${maintainers.length === 1 ? maintainers[0].name || 'unknown' : '0 maintainers'})`,
        dedupKey: `metadata:maintainers:few:${ctx.packageName}`,
        rawData: { count: maintainers.length },
      });
    }

    return evidence;
  }
}

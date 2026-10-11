import type { Scanner, ScanContext, Evidence } from '../types.js';

// Common visual homoglyphs
const HOMOGLYPH_MAP: Record<string, string[]> = {
  'o': ['0', 'O'],
  '0': ['o', 'O'],
  'l': ['1', 'I', 'i'],
  '1': ['l', 'I', 'i'],
  'i': ['1', 'l', 'I'],
  'm': ['rn', 'nn'],
  'w': ['vv'],
  'v': ['u'],
  'u': ['v'],
  'c': ['e'],
};

export function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1, // deletion
          dp[i][j - 1] + 1, // insertion
          dp[i - 1][j - 1] + 1, // substitution
        );
      }
    }
  }
  return dp[m][n];
}

export function isCharacterSwap(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const diffs: number[] = [];
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) diffs.push(i);
  }
  return diffs.length === 2 && a[diffs[0]] === b[diffs[1]] && a[diffs[1]] === b[diffs[0]];
}

export function isCharacterRepeat(a: string, b: string): boolean {
  // e.g., looodash vs lodash
  const collapse = (s: string) => s.replace(/(.)\1+/g, '$1');
  return collapse(a) === collapse(b) && a !== b;
}

export function hasHomoglyphMatch(candidate: string, target: string): boolean {
  if (candidate === target) return false;
  // Check if replacing mapped homoglyphs makes candidate equal to target
  let regexStr = '^';
  for (let i = 0; i < target.length; i++) {
    const ch = target[i].toLowerCase();
    const glyphs = HOMOGLYPH_MAP[ch] || [];
    const group = [ch, ...glyphs].map((g) => g.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    regexStr += `(?:${group})`;
  }
  regexStr += '$';
  try {
    return new RegExp(regexStr, 'i').test(candidate);
  } catch {
    return false;
  }
}

export interface TopPackagesData {
  version: string;
  source: string;
  packages: string[];
}

export class TyposquatScanner implements Scanner {
  readonly name = 'TyposquatScanner';

  private readonly popularPackages: string[];

  constructor(baselineData?: TopPackagesData) {
    if (baselineData?.packages) {
      this.popularPackages = baselineData.packages;
    } else {
      // Default top packages list
      this.popularPackages = [
        'lodash',
        'chalk',
        'react',
        'express',
        'axios',
        'commander',
        'typescript',
        'glob',
        'debug',
        'yargs',
        'dotenv',
        'webpack',
      ];
    }
  }

  async collect(ctx: ScanContext): Promise<Evidence[]> {
    const evidence: Evidence[] = [];
    const name = ctx.packageName.toLowerCase();

    // If identical to an existing legitimate package name, it's not a typosquat of itself
    for (let index = 0; index < this.popularPackages.length; index++) {
      const topPkg = this.popularPackages[index].toLowerCase();
      if (name === topPkg) {
        continue;
      }

      const dist = levenshteinDistance(name, topPkg);
      const isSwap = isCharacterSwap(name, topPkg);
      const isRepeat = isCharacterRepeat(name, topPkg);
      const isHomoglyph = hasHomoglyphMatch(name, topPkg);

      let reason = '';
      let isSuspicious = false;

      if (isSwap) {
        reason = `adjacent character swap from '${topPkg}', a top-ranked package (rank #${index + 1})`;
        isSuspicious = true;
      } else if (dist === 1) {
        reason = `1 edit from '${topPkg}', a top-ranked package (rank #${index + 1})`;
        isSuspicious = true;
      } else if (isRepeat) {
        reason = `character repetition/omission variation of '${topPkg}', a top-ranked package`;
        isSuspicious = true;
      } else if (isHomoglyph) {
        reason = `homoglyph / visually confusable character substitution of '${topPkg}'`;
        isSuspicious = true;
      } else if (dist === 2 && topPkg.length >= 6) {
        reason = `2 edits from popular package '${topPkg}'`;
        isSuspicious = true;
      }

      if (isSuspicious) {
        // Evaluate contextual corroborating signals:
        // Never auto-block on name similarity alone; confidence is raised only when combined with
        // other signals (new package, install script, low downloads).
        let baseConfidence = 0.5; // low initial confidence
        const signals: string[] = [];

        const versionDoc = (ctx.registryMetadata?.versions as Record<string, any>)?.[ctx.version] ||
          (ctx.registryMetadata as any);

        if (versionDoc?.scripts?.install || versionDoc?.scripts?.postinstall || versionDoc?.scripts?.preinstall) {
          signals.push('contains lifecycle install script');
          baseConfidence += 0.2;
        }

        if (ctx.registryMetadata?.time) {
          const createdStr = ctx.registryMetadata.time.created;
          if (createdStr) {
            const ageDays = (Date.now() - new Date(createdStr).getTime()) / (1000 * 60 * 60 * 24);
            if (ageDays < 30) {
              signals.push('newly created package (<30 days old)');
              baseConfidence += 0.2;
            }
          }
        }

        const confidence = Math.round(Math.min(0.9, baseConfidence) * 100) / 100;
        const explanation = signals.length > 0
          ? `Suspicious package name: ${reason}. Corroborating signals: ${signals.join(', ')}.`
          : `Suspicious package name: ${reason}. Note: confidence is kept low without corroborating signals (install scripts, new package).`;

        evidence.push({
          id: `typosquat-${topPkg}`,
          scanner: this.name,
          category: 'typosquat',
          severity: confidence >= 0.8 ? 'HIGH' : 'LOW',
          confidence,
          description: explanation,
          dedupKey: `typosquat:${name}:${topPkg}`,
          rawData: {
            targetPackage: topPkg,
            levenshteinDistance: dist,
            corroboratingSignals: signals,
          },
        });
        break; // matched most relevant top package
      }
    }

    return evidence;
  }
}

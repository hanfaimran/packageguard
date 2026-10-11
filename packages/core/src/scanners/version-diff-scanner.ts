import type { Scanner, ScanContext, Evidence } from '../types.js';
import { extractTarballInMemory, type ExtractedFile } from '../parsers/tarball-extractor.js';
import { StaticAnalyzer } from './static-analyzer.js';

export class VersionDiffScanner implements Scanner {
  readonly name = 'VersionDiffScanner';

  constructor(private readonly staticAnalyzer = new StaticAnalyzer()) {}

  async collect(ctx: ScanContext): Promise<Evidence[]> {
    const evidence: Evidence[] = [];

    if (!ctx.tarballBytes || !ctx.previousVersionTarballBytes) {
      return evidence;
    }

    let currentFiles: ExtractedFile[] = [];
    let previousFiles: ExtractedFile[] = [];

    try {
      [currentFiles, previousFiles] = await Promise.all([
        extractTarballInMemory(ctx.tarballBytes),
        extractTarballInMemory(ctx.previousVersionTarballBytes),
      ]);
    } catch {
      return evidence;
    }

    const prevFileMap = new Map<string, ExtractedFile>(previousFiles.map((f) => [f.path, f]));
    const currFileMap = new Map<string, ExtractedFile>(currentFiles.map((f) => [f.path, f]));

    // 1. Maintainer changes comparison
    const currMeta = ctx.registryMetadata;
    const prevMeta = ctx.previousVersionMetadata;
    if (currMeta && prevMeta) {
      const prevMaintainers = new Set(
        ((prevMeta.maintainers as Array<{ name: string }>) || []).map((m) => m.name),
      );
      const currMaintainers = (currMeta.maintainers as Array<{ name: string }>) || [];
      const newMaintainers = currMaintainers.filter((m) => !prevMaintainers.has(m.name));

      if (newMaintainers.length > 0 && prevMaintainers.size > 0) {
        evidence.push({
          id: `diff-new-maintainer-${newMaintainers[0].name}`,
          scanner: this.name,
          category: 'version-diff',
          severity: 'MEDIUM',
          confidence: 0.8,
          description: `New maintainer (${newMaintainers.map((m) => m.name).join(', ')}) added in ${ctx.version}, absent in previous version`,
          dedupKey: `version-diff:maintainer:added:${newMaintainers[0].name}`,
          rawData: {
            newMaintainers: newMaintainers.map((m) => m.name),
          },
        });
      }
    }

    // 2. Lifecycle install script changes / additions
    const currVersionDoc = ((currMeta?.versions as Record<string, any>)?.[ctx.version] || currMeta) as any;
    const prevVersionKey = Object.keys((prevMeta?.versions as Record<string, any>) || {})[0];
    const prevVersionDoc = (prevVersionKey
      ? (prevMeta?.versions as Record<string, any>)?.[prevVersionKey]
      : prevMeta) as any;

    const currScripts: Record<string, string> = currVersionDoc?.scripts || {};
    const prevScripts: Record<string, string> = prevVersionDoc?.scripts || {};

    const installKeys = ['preinstall', 'install', 'postinstall'];
    for (const key of installKeys) {
      if (currScripts[key] && !prevScripts[key]) {
        evidence.push({
          id: `diff-added-script-${key}`,
          scanner: this.name,
          category: 'version-diff',
          severity: 'HIGH',
          confidence: 0.9,
          description: `${key} script added in ${ctx.version}, absent in previous version: "${currScripts[key]}"`,
          dedupKey: `lifecycle:script:${key}`,
          rawData: {
            script: key,
            currentCommand: currScripts[key],
          },
        });
      } else if (currScripts[key] && prevScripts[key] && currScripts[key] !== prevScripts[key]) {
        evidence.push({
          id: `diff-changed-script-${key}`,
          scanner: this.name,
          category: 'version-diff',
          severity: 'MEDIUM',
          confidence: 0.85,
          description: `${key} script modified in ${ctx.version} (was: "${prevScripts[key]}", now: "${currScripts[key]}")`,
          dedupKey: `lifecycle:script:${key}`,
          rawData: {
            script: key,
            previousCommand: prevScripts[key],
            currentCommand: currScripts[key],
          },
        });
      }
    }

    // 3. Newly added dependencies
    const currDeps: Record<string, string> = currVersionDoc?.dependencies || {};
    const prevDeps: Record<string, string> = prevVersionDoc?.dependencies || {};
    const addedDeps = Object.keys(currDeps).filter((d) => !prevDeps[d]);
    if (addedDeps.length > 0) {
      evidence.push({
        id: 'diff-added-dependencies',
        scanner: this.name,
        category: 'version-diff',
        severity: 'LOW',
        confidence: 0.7,
        description: `New dependencies introduced in ${ctx.version}: ${addedDeps.join(', ')}`,
        dedupKey: `version-diff:deps:added:${addedDeps.sort().join(',')}`,
        rawData: { addedDeps },
      });
    }

    // 4. Identify added or modified files
    const changedOrAddedFiles: ExtractedFile[] = [];
    for (const [path, currFile] of currFileMap.entries()) {
      const prevFile = prevFileMap.get(path);
      if (!prevFile || prevFile.content !== currFile.content) {
        changedOrAddedFiles.push(currFile);
      }
    }

    // 5. Large size jumps or obfuscation additions
    const prevTotalSize = previousFiles.reduce((acc, f) => acc + f.size, 0);
    const currTotalSize = currentFiles.reduce((acc, f) => acc + f.size, 0);
    if (prevTotalSize > 0 && currTotalSize > prevTotalSize * 3 && currTotalSize > 50000) {
      evidence.push({
        id: 'diff-size-jump',
        scanner: this.name,
        category: 'version-diff',
        severity: 'MEDIUM',
        confidence: 0.75,
        description: `Significant package size jump: increased from ${prevTotalSize} bytes to ${currTotalSize} bytes (>3x increase)`,
        dedupKey: 'version-diff:size:jump',
        rawData: { prevTotalSize, currTotalSize },
      });
    }

    // 6. Run StaticAnalyzer on ADDED/CHANGED files only
    if (changedOrAddedFiles.length > 0) {
      const staticDiffEvidence = this.staticAnalyzer.analyzeFiles(changedOrAddedFiles, ctx);
      for (const ev of staticDiffEvidence) {
        // Tag as version-diff category with enriched description
        evidence.push({
          ...ev,
          id: `diff-${ev.id}`,
          scanner: this.name,
          category: 'version-diff',
          description: `[In added/modified file] ${ev.description}`,
        });
      }
    }

    return evidence;
  }
}

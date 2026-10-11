import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import type { Scanner, ScanContext, Evidence, Severity } from '../types.js';
import { extractTarballInMemory, type ExtractedFile } from '../parsers/tarball-extractor.js';

export interface RawSignal {
  ruleId: string;
  category: 'exec' | 'eval' | 'env' | 'obfuscation' | 'network' | 'credential';
  description: string;
  file: string;
  line: number;
  snippet: string;
}

export function calculateEntropy(str: string): number {
  if (!str) return 0;
  const freqs: Record<string, number> = {};
  for (const ch of str) {
    freqs[ch] = (freqs[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freqs)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export class StaticAnalyzer implements Scanner {
  readonly name = 'StaticAnalyzer';

  async collect(ctx: ScanContext): Promise<Evidence[]> {
    if (!ctx.tarballBytes || ctx.tarballBytes.length === 0) {
      return [];
    }

    let files: ExtractedFile[];
    try {
      files = await extractTarballInMemory(ctx.tarballBytes);
    } catch {
      return [];
    }

    return this.analyzeFiles(files, ctx);
  }

  analyzeFiles(files: ExtractedFile[], ctx: ScanContext): Evidence[] {
    const rawSignals: RawSignal[] = [];

    // Identify which files/commands are install scripts
    const versionDoc = (ctx.registryMetadata?.versions as Record<string, any>)?.[ctx.version] ||
      (ctx.registryMetadata as any);
    const scripts = versionDoc?.scripts || {};
    const installScriptCommands: string[] = [];
    const installScriptFiles = new Set<string>();

    for (const [key, cmd] of Object.entries(scripts)) {
      if (['preinstall', 'install', 'postinstall'].includes(key) && typeof cmd === 'string') {
        installScriptCommands.push(cmd);
        // Match files invoked in the lifecycle command, e.g. "node ./scripts/postinstall.js", "node scripts/postinstall.js", "bash install.sh", "sh ./setup.sh"
        const fileMatches = cmd.matchAll(/(?:node|sh|bash)\s+([^\s;&|]+)/g);
        for (const match of fileMatches) {
          if (match[1]) {
            const cleanPath = match[1].replace(/^\.\//, '').trim();
            installScriptFiles.add(cleanPath);
          }
        }
      }
    }

    // Check raw install script commands for dangerous patterns (curl|sh, node -e)
    for (const cmd of installScriptCommands) {
      if (/curl\s+.*\|\s*(?:bash|sh)/i.test(cmd) || /wget\s+.*\|\s*(?:bash|sh)/i.test(cmd)) {
        rawSignals.push({
          ruleId: 'install-script-curl-pipe-sh',
          category: 'exec',
          description: 'Lifecycle script pipes remote curl/wget download directly to shell',
          file: 'package.json:scripts',
          line: 1,
          snippet: cmd,
        });
      }
      if (/node\s+-e\s+/i.test(cmd)) {
        rawSignals.push({
          ruleId: 'install-script-node-eval',
          category: 'eval',
          description: 'Lifecycle script invokes inline node execution via -e flag',
          file: 'package.json:scripts',
          line: 1,
          snippet: cmd,
        });
      }
    }

    // Inspect files statically
    for (const file of files) {
      const isJs = /\.(js|cjs|mjs|ts)$/i.test(file.path);
      const isTestFile = /(test|spec|\.test\.|\.spec\.|__tests__)/i.test(file.path);
      const isDoc = /\.(md|txt|html|rst)$/i.test(file.path);

      if (isDoc) continue;

      // Entropy & obfuscation regex scan
      const lines = file.content.split('\n');
      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx];
        const lineNum = lineIdx + 1;

        // Long base64 / hex string heuristics
        const base64Match = line.match(/(?:['"])([A-Za-z0-9+/]{80,}={0,2})(?:['"])/);
        if (base64Match) {
          rawSignals.push({
            ruleId: 'blob-base64',
            category: 'obfuscation',
            description: 'Long base64-encoded string literal detected (>80 chars)',
            file: file.path,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
        }

        const hexMatch = line.match(/(?:['"])([0-9a-fA-F]{80,})(?:['"])/);
        if (hexMatch) {
          rawSignals.push({
            ruleId: 'blob-hex',
            category: 'obfuscation',
            description: 'Long hex-encoded string literal detected (>80 chars)',
            file: file.path,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
        }

        // Outbound URL / IP patterns (e.g. http://exfil.invalid or IP endpoints)
        const urlMatch = line.match(/https?:\/\/[a-zA-Z0-9.\-_]+(?::\d+)?/);
        if (urlMatch && !isTestFile && !line.includes('schema.org') && !line.includes('github.com')) {
          rawSignals.push({
            ruleId: 'outbound-url',
            category: 'network',
            description: `Outbound endpoint or URL detected: ${urlMatch[0]}`,
            file: file.path,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
        }

        // Credential file path access (.npmrc, .ssh, .aws)
        if (/\.(npmrc|ssh|aws\/credentials)/i.test(line)) {
          rawSignals.push({
            ruleId: 'credential-path-access',
            category: 'credential',
            description: 'Reference to sensitive credential path (.npmrc, .ssh, .aws)',
            file: file.path,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
        }

        // High Shannon entropy line heuristic (> 5.2 on long line)
        if (line.length > 100) {
          const ent = calculateEntropy(line);
          if (ent > 5.4) {
            rawSignals.push({
              ruleId: 'high-entropy-string',
              category: 'obfuscation',
              description: `High Shannon entropy code detected (${ent.toFixed(2)})`,
              file: file.path,
              line: lineNum,
              snippet: line.trim().slice(0, 120),
            });
          }
        }
      }

      // AST parser walk for JavaScript files
      if (isJs) {
        try {
          const ast = acorn.parse(file.content, {
            ecmaVersion: 'latest',
            sourceType: 'module',
            locations: true,
          });

          walk.simple(ast, {
            CallExpression(node: any) {
              const line = node.loc?.start?.line || 1;
              const callee = node.callee;

              // eval(...)
              if (callee.type === 'Identifier' && callee.name === 'eval') {
                rawSignals.push({
                  ruleId: 'eval-call',
                  category: 'eval',
                  description: 'Call to dynamic code evaluator eval()',
                  file: file.path,
                  line,
                  snippet: 'eval(...)',
                });
              }

              // Function(...) or new Function(...)
              if (callee.type === 'Identifier' && callee.name === 'Function') {
                rawSignals.push({
                  ruleId: 'function-constructor',
                  category: 'eval',
                  description: 'Invocation of Function constructor for dynamic code generation',
                  file: file.path,
                  line,
                  snippet: 'Function(...)',
                });
              }

              // child_process (exec, execSync, spawn)
              if (
                callee.type === 'MemberExpression' &&
                callee.property &&
                ['exec', 'execSync', 'spawn', 'spawnSync'].includes(callee.property.name)
              ) {
                rawSignals.push({
                  ruleId: 'child-process-exec',
                  category: 'exec',
                  description: `Execution of system child process via child_process.${callee.property.name}()`,
                  file: file.path,
                  line,
                  snippet: `child_process.${callee.property.name}(...)`,
                });
              }
            },
            MemberExpression(node: any) {
              const line = node.loc?.start?.line || 1;
              // process.env
              if (
                node.object?.type === 'Identifier' &&
                node.object.name === 'process' &&
                node.property?.type === 'Identifier' &&
                node.property.name === 'env'
              ) {
                rawSignals.push({
                  ruleId: 'process-env-access',
                  category: 'env',
                  description: 'Access to process.env environment variables',
                  file: file.path,
                  line,
                  snippet: 'process.env',
                });
              }
            },
          });
        } catch {
          // If AST parsing fails (e.g. TS syntax or syntax error), regex fallback was already executed above
        }
      }
    }

    // Correlation step:
    // Single signal: LOW severity, low confidence (0.4 - 0.5)
    // Multiple signals in the same file or lifecycle script:
    // (e.g. env access + base64 decode + outbound network call, especially inside install script) => CRITICAL, confidence 0.95+
    return this.correlateSignals(rawSignals, installScriptFiles);
  }

  correlateSignals(signals: RawSignal[], installScriptFiles: Set<string>): Evidence[] {
    const evidenceList: Evidence[] = [];
    const byFile = new Map<string, RawSignal[]>();

    for (const sig of signals) {
      const list = byFile.get(sig.file) || [];
      list.push(sig);
      byFile.set(sig.file, list);
    }

    for (const [filePath, fileSignals] of byFile.entries()) {
      const isInstallScript = installScriptFiles.has(filePath) || filePath.startsWith('package.json:scripts');
      const isTestFile = /(test|spec|\.test\.|\.spec\.|__tests__)/i.test(filePath);

      const uniqueCategories = new Set(fileSignals.map((s) => s.category));
      const hasEnv = uniqueCategories.has('env') || uniqueCategories.has('credential');
      const hasObfuscationOrEval = uniqueCategories.has('obfuscation') || uniqueCategories.has('eval');
      const hasOutbound = uniqueCategories.has('network');
      const hasExec = uniqueCategories.has('exec');

      // Check for exfiltration pattern: env/credential + obfuscation/eval + network
      const isExfiltrationPattern = hasEnv && (hasObfuscationOrEval || hasExec) && hasOutbound;

      if (isExfiltrationPattern && isInstallScript) {
        // High-confidence malicious exfiltration inside install script
        evidenceList.push({
          id: `static-exfil-install-${filePath}`,
          scanner: this.name,
          category: 'static-analysis',
          severity: 'CRITICAL',
          confidence: 0.98,
          description: `Correlated credential exfiltration pattern detected inside lifecycle install script (${filePath}): environment/credential access + obfuscation/execution + outbound network transmission`,
          location: { file: filePath, line: fileSignals[0].line },
          snippet: fileSignals.map((s) => s.snippet).join(' | ').slice(0, 200),
          dedupKey: `static:correlated:exfiltration:${filePath}`,
          rawData: { signals: fileSignals, isInstallScript: true },
        });
      } else if (isExfiltrationPattern) {
        evidenceList.push({
          id: `static-exfil-${filePath}`,
          scanner: this.name,
          category: 'static-analysis',
          severity: 'HIGH',
          confidence: 0.85,
          description: `Correlated suspicious data collection pattern in ${filePath}: environment access combined with dynamic code and outbound network connection`,
          location: { file: filePath, line: fileSignals[0].line },
          snippet: fileSignals.map((s) => s.snippet).join(' | ').slice(0, 200),
          dedupKey: `static:correlated:exfiltration:${filePath}`,
          rawData: { signals: fileSignals, isInstallScript: false },
        });
      } else if (fileSignals.length >= 2 && !isTestFile) {
        // Multiple signals in non-test file raise confidence slightly to MEDIUM
        const primarySig = fileSignals[0];
        evidenceList.push({
          id: `static-multi-${primarySig.ruleId}-${filePath}`,
          scanner: this.name,
          category: 'static-analysis',
          severity: isInstallScript ? 'HIGH' : 'MEDIUM',
          confidence: isInstallScript ? 0.8 : 0.65,
          description: `Multiple suspicious signals in ${filePath}: ${fileSignals.map((s) => s.description).join('; ')}`,
          location: { file: filePath, line: primarySig.line },
          snippet: primarySig.snippet,
          dedupKey: `static:correlated:multi:${filePath}`,
          rawData: { signals: fileSignals },
        });
      } else {
        // Single signal: stays LOW severity and low confidence (or INFO in test files)
        for (const sig of fileSignals) {
          const severity: Severity = isTestFile ? 'INFO' : 'LOW';
          const confidence = isTestFile ? 0.2 : 0.4;
          evidenceList.push({
            id: `static-${sig.ruleId}-${sig.file}-${sig.line}`,
            scanner: this.name,
            category: 'static-analysis',
            severity,
            confidence,
            description: `${sig.description} in ${sig.file}:${sig.line}`,
            location: { file: sig.file, line: sig.line },
            snippet: sig.snippet,
            dedupKey: `static:signal:${sig.ruleId}:${sig.file}:${sig.line}`,
            rawData: { signal: sig },
          });
        }
      }
    }

    return evidenceList;
  }
}

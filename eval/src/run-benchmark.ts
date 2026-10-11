import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { scanPackage, type ScanContext, type Report, type OsvClient } from '@packageguard/core';
import { generateAllFixtures } from './fixtures/generator.js';
import { FakeRegistryServer } from './fake-registry.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface BenchmarkMetrics {
  total: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1: number;
  detectionRate: number;
  falsePositiveRate: number;
  perPackage: Array<{
    package: string;
    version: string;
    groundTruth: 'benign' | 'malicious';
    verdict: string;
    riskScore: number;
    verificationStatus: string;
    classification: 'TP' | 'FP' | 'TN' | 'FN';
  }>;
}

export async function runBenchmark(): Promise<BenchmarkMetrics> {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

  const fixtures = generateAllFixtures(privPem);
  const server = new FakeRegistryServer({ port: 4001, fixtures });
  const serverUrl = await server.start();

  const labelsRaw = fs.readFileSync(path.resolve(__dirname, '../labels.json'), 'utf-8');
  const labels: Record<string, { groundTruth: 'benign' | 'malicious'; expectedVerdict: string }> =
    JSON.parse(labelsRaw);

  // Mock OSV client to return vulnerability for vulnerable-pkg
  const mockOsvClient = {
    queryPackage: async (name: string) => {
      if (name === 'vulnerable-pkg') {
        return [
          {
            id: 'GHSA-vuln-eval-1',
            summary: 'Remote Code Execution Flaw in parser',
            database_specific: { severity: 'CRITICAL' },
          },
        ];
      }
      return [];
    },
    queryBatch: async () => ({ results: [] }),
  } as unknown as OsvClient;

  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  const perPackage: BenchmarkMetrics['perPackage'] = [];

  try {
    for (const [key, meta] of Object.entries(labels)) {
      const [name, version] = key.split('@');
      const fixture = fixtures[key];

      let prevTarball: Buffer | undefined;
      let prevMeta: Record<string, unknown> | undefined;

      if (key === 'event-stream-lite@1.0.1') {
        const v1Fixture = fixtures['event-stream-lite@1.0.0'];
        prevTarball = v1Fixture.tarballBytes;
        prevMeta = v1Fixture.packageDocument;
      }

      const ctx: ScanContext = {
        packageName: name,
        ecosystem: 'npm',
        version,
        tarballBytes: fixture.tarballBytes,
        registryMetadata: fixture.packageDocument,
        previousVersionTarballBytes: prevTarball,
        previousVersionMetadata: prevMeta,
        registryUrl: serverUrl,
      };

      const report: Report = await scanPackage(ctx, {
        trustedPublicKeys: { 'packageguard-eval-key-1': pubPem },
        osvClient: mockOsvClient,
      });

      // Binary classification mapping:
      // Flagged as threat = Block or Review
      // Benign pass = Safe
      const flagged = report.verdict === 'Block' || report.verdict === 'Review';
      const actualMalicious = meta.groundTruth === 'malicious';

      let classification: 'TP' | 'FP' | 'TN' | 'FN';
      if (actualMalicious && flagged) {
        classification = 'TP';
        tp++;
      } else if (!actualMalicious && flagged) {
        classification = 'FP';
        fp++;
      } else if (!actualMalicious && !flagged) {
        classification = 'TN';
        tn++;
      } else {
        classification = 'FN';
        fn++;
      }

      perPackage.push({
        package: name,
        version,
        groundTruth: meta.groundTruth,
        verdict: report.verdict,
        riskScore: report.riskScore,
        verificationStatus: report.verificationStatus,
        classification,
      });
    }
  } finally {
    await server.stop();
  }

  const total = tp + fp + tn + fn;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 1;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const detectionRate = recall;
  const falsePositiveRate = fp + tn > 0 ? fp / (fp + tn) : 0;

  const results: BenchmarkMetrics = {
    total,
    truePositives: tp,
    falsePositives: fp,
    trueNegatives: tn,
    falseNegatives: fn,
    precision,
    recall,
    f1,
    detectionRate,
    falsePositiveRate,
    perPackage,
  };

  // Write reports to eval/report.json and eval/report.md
  const reportJsonPath = path.resolve(__dirname, '../report.json');
  const reportMdPath = path.resolve(__dirname, '../report.md');

  fs.writeFileSync(reportJsonPath, JSON.stringify(results, null, 2));

  const mdContent = `# PackageGuard Benchmark Evaluation Report

## 1. Summary Metrics
- **Total Evaluated Packages**: ${total}
- **True Positives (TP)**: ${tp}
- **False Positives (FP)**: ${fp}
- **True Negatives (TN)**: ${tn}
- **False Negatives (FN)**: ${fn}
- **Precision**: ${(precision * 100).toFixed(1)}%
- **Recall / Detection Rate**: ${(recall * 100).toFixed(1)}%
- **F1 Score**: ${f1.toFixed(3)}
- **False Positive Rate (FPR)**: ${(falsePositiveRate * 100).toFixed(1)}%

## 2. Per-Package Evaluation Matrix
| Package | Version | Ground Truth | Verdict | Score | Verification | Classification |
|---|---|---|---|---|---|---|
${perPackage
  .map(
    (p) =>
      `| ${p.package} | ${p.version} | ${p.groundTruth} | **${p.verdict}** | ${p.riskScore} | ${p.verificationStatus} | ${p.classification} |`,
  )
  .join('\n')}

## 3. Limitations & Real-World Caveats
> [!IMPORTANT]
> **Evaluation Limitations Disclaimer**:
> This benchmark operates against synthetic, defanged test fixtures engineered to model real-world attack vectors (e.g., event-stream supply chain injection, typosquatting, metadata manipulation, hash tampering, and known CVEs).
> **Synthetic fixtures do not establish real-world detection accuracy** in production ecosystems. Real-world adversaries employ dynamic evasion techniques, polymorphic obfuscation, time-delayed staging, multi-stage downloads, and context-dependent activation that cannot be fully captured in static laboratory suites alone.
`;

  fs.writeFileSync(reportMdPath, mdContent);

  return results;
}

if (process.argv[1]?.endsWith('run-benchmark.ts')) {
  runBenchmark().then((res) => {
    console.log('Benchmark finished:', res);
  });
}

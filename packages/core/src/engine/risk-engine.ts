import type {
  Evidence,
  EvidenceCategory,
  Report,
  RiskBreakdownItem,
  RemediationSuggestion,
  VerificationStatus,
  Verdict,
} from '../types.js';

// Base severity deduction points
const SEVERITY_BASE_PENALTY: Record<string, number> = {
  CRITICAL: 35,
  HIGH: 20,
  MEDIUM: 10,
  LOW: 4,
  INFO: 0,
};

// Category deduction caps to avoid unbounded penalty skewing
const CATEGORY_CAPS: Record<EvidenceCategory, number> = {
  metadata: 25,
  vulnerability: 50,
  integrity: 60,
  typosquat: 30,
  'static-analysis': 60,
  'version-diff': 35,
  policy: 50,
};

export class RiskEngine {
  evaluate(
    packageName: string,
    version: string,
    dedupedEvidence: Evidence[],
    verificationStatus: VerificationStatus,
    policyHardBlocks: string[] = [],
  ): Report {
    const hardBlocks: string[] = [...policyHardBlocks];
    const categoryTotals: Record<EvidenceCategory, number> = {
      metadata: 0,
      vulnerability: 0,
      integrity: 0,
      typosquat: 0,
      'static-analysis': 0,
      'version-diff': 0,
      policy: 0,
    };

    const breakdown: RiskBreakdownItem[] = [];
    const remediation: RemediationSuggestion[] = [];

    // 1. Process Hard Blocks
    // Hash mismatch or invalid registry signature
    if (verificationStatus === 'Unverified') {
      const mismatchEv = dedupedEvidence.find(
        (e) => e.category === 'integrity' && e.severity === 'CRITICAL',
      );
      if (mismatchEv) {
        hardBlocks.push(`Integrity verification failed: ${mismatchEv.description}`);
      } else {
        hardBlocks.push('Package integrity or authenticity could not be verified (Unverified)');
      }
    }

    // Critical known vulnerability
    const criticalVuln = dedupedEvidence.find(
      (e) => e.category === 'vulnerability' && e.severity === 'CRITICAL',
    );
    if (criticalVuln) {
      hardBlocks.push(`Critical vulnerability detected: ${criticalVuln.description}`);
    }

    // Correlated exfiltration pattern in lifecycle script
    const exfilInstall = dedupedEvidence.find(
      (e) =>
        e.category === 'static-analysis' &&
        e.severity === 'CRITICAL' &&
        e.dedupKey.includes('exfiltration'),
    );
    if (exfilInstall) {
      hardBlocks.push(
        `Correlated credential exfiltration detected in package: ${exfilInstall.description}`,
      );
    }

    // 2. Score Deduction Engine
    for (const ev of dedupedEvidence) {
      const base = SEVERITY_BASE_PENALTY[ev.severity] || 0;
      // Scaled by severity x confidence
      const rawPoints = Math.round(base * ev.confidence);

      if (rawPoints > 0) {
        const cat = ev.category;
        const currentCatTotal = categoryTotals[cat] || 0;
        const cap = CATEGORY_CAPS[cat] || 40;

        // Apply deduction respecting category cap
        const allowablePoints = Math.max(0, Math.min(rawPoints, cap - currentCatTotal));
        if (allowablePoints > 0) {
          categoryTotals[cat] = currentCatTotal + allowablePoints;
          breakdown.push({
            category: cat,
            reason: ev.description,
            evidenceRefs: [ev.id],
            confidence: ev.confidence,
            points: allowablePoints,
          });
        }
      }

      // Generate remediation suggestions
      if (ev.category === 'vulnerability') {
        remediation.push({
          issue: ev.description,
          recommendation: `Upgrade ${packageName} or transitive dependencies to patched versions.`,
        });
      } else if (ev.category === 'typosquat') {
        remediation.push({
          issue: ev.description,
          recommendation: `Double check spelling of package name against trusted repositories.`,
        });
      } else if (ev.category === 'integrity') {
        remediation.push({
          issue: ev.description,
          recommendation: `Do not install! Tarball bytes do not match published cryptographic hash.`,
        });
      } else if (ev.category === 'static-analysis' && ev.severity === 'CRITICAL') {
        remediation.push({
          issue: ev.description,
          recommendation: `Package contains malicious data harvesting payloads. Quarantine immediately.`,
        });
      }
    }

    // Compute final riskScore (starts at 100, higher = lower observed risk)
    const totalDeduction = Object.values(categoryTotals).reduce((a, b) => a + b, 0);
    const riskScore = Math.max(0, 100 - totalDeduction);

    // 3. Verdict Logic (separate from score)
    // Safe requires score >= 80 AND verificationStatus != Unverified AND no hard blocks.
    // A package with score 95 but failed integrity is Block, not Safe. Review for everything in between.
    let verdict: Verdict;
    if (hardBlocks.length > 0) {
      verdict = 'Block';
    } else if (riskScore >= 80 && verificationStatus !== 'Unverified') {
      verdict = 'Safe';
    } else {
      verdict = 'Review';
    }

    return {
      package: packageName,
      version,
      riskScore,
      verdict,
      verificationStatus,
      breakdown,
      hardBlocks,
      evidence: dedupedEvidence,
      remediation,
    };
  }
}

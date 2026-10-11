import YAML from 'yaml';
import type { Evidence, VerificationStatus } from '../types.js';

export interface GuardPolicy {
  name?: string;
  minScore?: number;
  requireProvenance?: boolean;
  banInstallScripts?: boolean;
  minVerificationStatus?: VerificationStatus;
  allowlist?: string[];
}

export interface PolicyEvaluationResult {
  passed: boolean;
  isAllowed: boolean;
  violations: string[];
  hardBlocks: string[];
}

export function parsePolicyYaml(yamlContent: string): GuardPolicy {
  try {
    const doc = YAML.parse(yamlContent);
    return (doc || {}) as GuardPolicy;
  } catch (err) {
    throw new Error(`Failed to parse policy YAML: ${(err as Error).message}`);
  }
}

export class PolicyEngine {
  constructor(private readonly policy: GuardPolicy = {}) {}

  evaluate(
    packageName: string,
    version: string,
    riskScore: number,
    verificationStatus: VerificationStatus,
    evidenceList: Evidence[],
  ): PolicyEvaluationResult {
    // Check allowlist first
    if (this.policy.allowlist && this.policy.allowlist.includes(packageName)) {
      return {
        passed: true,
        isAllowed: true,
        violations: [],
        hardBlocks: [],
      };
    }

    const violations: string[] = [];
    const hardBlocks: string[] = [];

    // 1. Min score requirement
    if (typeof this.policy.minScore === 'number' && riskScore < this.policy.minScore) {
      violations.push(`Risk score ${riskScore} is below policy minimum required score of ${this.policy.minScore}`);
    }

    // 2. Minimum verification status
    if (this.policy.minVerificationStatus) {
      const hierarchy: Record<VerificationStatus, number> = {
        Unverified: 1,
        PartiallyVerified: 2,
        Verified: 3,
      };
      const actualLvl = hierarchy[verificationStatus] || 0;
      const requiredLvl = hierarchy[this.policy.minVerificationStatus] || 0;

      if (actualLvl < requiredLvl) {
        violations.push(
          `Verification status '${verificationStatus}' does not meet required minimum '${this.policy.minVerificationStatus}'`,
        );
        hardBlocks.push(`Policy requires minimum verification status: ${this.policy.minVerificationStatus}`);
      }
    }

    // 3. Require Provenance (Sigstore)
    if (this.policy.requireProvenance && verificationStatus !== 'Verified') {
      violations.push(`Cryptographic package provenance attestation is required by policy but not verified`);
      hardBlocks.push('Policy requires verified provenance attestation');
    }

    // 4. Ban install scripts
    if (this.policy.banInstallScripts) {
      const scriptEv = evidenceList.find((e) => e.dedupKey.startsWith('lifecycle:script:'));
      if (scriptEv) {
        violations.push(`Policy strictly bans packages with install scripts: ${scriptEv.description}`);
        hardBlocks.push(`Policy violation: install scripts are disallowed in this environment`);
      }
    }

    return {
      passed: violations.length === 0,
      isAllowed: false,
      violations,
      hardBlocks,
    };
  }
}

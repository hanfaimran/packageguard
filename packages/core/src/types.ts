export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type EvidenceCategory =
  | 'metadata'
  | 'vulnerability'
  | 'integrity'
  | 'typosquat'
  | 'static-analysis'
  | 'version-diff'
  | 'policy';

export interface Location {
  file: string;
  line?: number;
}

export interface Evidence {
  id: string;
  scanner: string;
  category: EvidenceCategory;
  severity: Severity;
  confidence: number; // 0.0 - 1.0
  description: string;
  location?: Location;
  snippet?: string;
  dedupKey: string;
  rawData?: Record<string, unknown>;
  sources?: string[];
}

export type VerificationStatus = 'Verified' | 'PartiallyVerified' | 'Unverified';

export type Verdict = 'Safe' | 'Review' | 'Block';

export interface ScanContext {
  packageName: string;
  ecosystem: 'npm';
  version: string;
  lockfileContent?: string;
  registryUrl?: string;
  tarballBytes?: Buffer;
  registryMetadata?: Record<string, unknown>;
  previousVersionMetadata?: Record<string, unknown>;
  previousVersionTarballBytes?: Buffer;
}

export interface Scanner {
  readonly name: string;
  collect(ctx: ScanContext): Promise<Evidence[]>;
}

export interface RiskBreakdownItem {
  category: EvidenceCategory;
  reason: string;
  evidenceRefs: string[];
  confidence: number;
  points: number;
}

export interface RemediationSuggestion {
  issue: string;
  recommendation: string;
}

export interface Report {
  package: string;
  version: string;
  riskScore: number; // 0 - 100 (higher = lower observed risk)
  verdict: Verdict;
  verificationStatus: VerificationStatus;
  breakdown: RiskBreakdownItem[];
  hardBlocks: string[];
  evidence: Evidence[];
  remediation: RemediationSuggestion[];
  policyApplied?: {
    name?: string;
    passed: boolean;
    violations: string[];
  };
}

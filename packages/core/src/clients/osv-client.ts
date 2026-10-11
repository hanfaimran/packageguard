import type { Severity } from '../types.js';

export interface OsvPackageQuery {
  package: {
    name: string;
    ecosystem: string;
  };
  version?: string;
}

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{
    type: string;
    score: string;
  }>;
  database_specific?: {
    severity?: string;
    cvss?: {
      score?: number;
      vectorString?: string;
    };
  };
}

export interface OsvBatchResponse {
  results: Array<{
    vulns?: OsvVulnerability[];
  }>;
}

export function cvssScoreToSeverity(score: number): Severity {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'INFO';
}

export function normalizeOsvSeverity(vuln: OsvVulnerability): Severity {
  // Check database_specific.severity
  const dbSev = vuln.database_specific?.severity?.toUpperCase();
  if (dbSev) {
    if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(dbSev)) {
      return dbSev as Severity;
    }
  }

  // Check database_specific.cvss.score
  if (typeof vuln.database_specific?.cvss?.score === 'number') {
    return cvssScoreToSeverity(vuln.database_specific.cvss.score);
  }

  // Check severity array (CVSS_V3 score parsing or CVSS_V2)
  if (vuln.severity && vuln.severity.length > 0) {
    for (const item of vuln.severity) {
      if (item.score) {
        // e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" or numerical
        const num = parseFloat(item.score);
        if (!isNaN(num)) {
          return cvssScoreToSeverity(num);
        }
      }
    }
  }

  return 'MEDIUM'; // Default fallback
}

export class OsvClient {
  constructor(private readonly baseUrl: string = 'https://api.osv.dev/v1') {}

  async queryPackage(name: string, version: string, ecosystem = 'npm'): Promise<OsvVulnerability[]> {
    const url = `${this.baseUrl.replace(/\/$/, '')}/query`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package: { name, ecosystem },
        version,
      }),
    });
    if (!res.ok) {
      throw new Error(`OSV API query failed: ${res.status} ${res.statusText}`);
    }
    const data = (await res.json()) as { vulns?: OsvVulnerability[] };
    return data.vulns || [];
  }

  async queryBatch(queries: OsvPackageQuery[]): Promise<OsvBatchResponse> {
    const url = `${this.baseUrl.replace(/\/$/, '')}/querybatch`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
    });
    if (!res.ok) {
      throw new Error(`OSV API batch query failed: ${res.status} ${res.statusText}`);
    }
    return (await res.json()) as OsvBatchResponse;
  }
}

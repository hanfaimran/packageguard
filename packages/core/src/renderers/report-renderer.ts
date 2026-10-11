import type { Report } from '../types.js';

export function renderJsonReport(report: Report): string {
  return JSON.stringify(report, null, 2);
}

export function renderTerminalReport(report: Report): string {
  const lines: string[] = [];

  const verdictBadge =
    report.verdict === 'Safe'
      ? '[SAFE]'
      : report.verdict === 'Block'
        ? '[BLOCK]'
        : '[REVIEW]';

  lines.push('================================================================');
  lines.push(`PACKAGEGUARD TRUST REPORT: ${report.package}@${report.version}`);
  lines.push('================================================================');
  lines.push(`Verdict:             ${verdictBadge} ${report.verdict.toUpperCase()}`);
  lines.push(`Risk Score:          ${report.riskScore}/100 (Higher = lower observed risk)`);
  lines.push(`Verification Status: ${report.verificationStatus}`);

  if (report.policyApplied) {
    lines.push(`Policy Status:       ${report.policyApplied.passed ? 'PASSED' : 'FAILED'}`);
    if (report.policyApplied.violations.length > 0) {
      lines.push('Policy Violations:');
      for (const v of report.policyApplied.violations) {
        lines.push(`  * ${v}`);
      }
    }
  }

  if (report.hardBlocks.length > 0) {
    lines.push('\nHARD BLOCKS TRIGGERED:');
    for (const hb of report.hardBlocks) {
      lines.push(`  ! ${hb}`);
    }
  }

  if (report.breakdown.length > 0) {
    lines.push('\nRISK BREAKDOWN DEDUCTIONS:');
    for (const b of report.breakdown) {
      lines.push(`  - [${b.category}] -${b.points} pts (conf: ${b.confidence}): ${b.reason}`);
    }
  }

  if (report.evidence.length > 0) {
    lines.push(`\nEVIDENCE ITEMS (${report.evidence.length}):`);
    for (const ev of report.evidence) {
      const loc = ev.location ? ` (${ev.location.file}${ev.location.line ? `:${ev.location.line}` : ''})` : '';
      lines.push(`  * [${ev.severity}] [${ev.category}] ${ev.description}${loc}`);
      if (ev.snippet) {
        lines.push(`      Snippet: ${ev.snippet}`);
      }
      if (ev.sources && ev.sources.length > 1) {
        lines.push(`      Corroborated by: ${ev.sources.join(', ')}`);
      }
    }
  }

  if (report.remediation.length > 0) {
    lines.push('\nREMEDIATION SUGGESTIONS:');
    for (const rem of report.remediation) {
      lines.push(`  > ${rem.issue}`);
      lines.push(`    Action: ${rem.recommendation}`);
    }
  }

  lines.push('================================================================');
  return lines.join('\n');
}

import type { Evidence, Severity } from '../types.js';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export function deduplicateEvidence(evidenceList: Evidence[]): Evidence[] {
  const dedupMap = new Map<string, Evidence>();

  for (const item of evidenceList) {
    const existing = dedupMap.get(item.dedupKey);

    if (!existing) {
      // First occurrence of this dedupKey
      dedupMap.set(item.dedupKey, {
        ...item,
        sources: [item.scanner],
      });
      continue;
    }

    // Existing entry found: merge sources
    const mergedSources = Array.from(new Set([...(existing.sources || [existing.scanner]), item.scanner]));

    // Determine higher severity
    const existingWeight = SEVERITY_WEIGHTS[existing.severity] || 0;
    const currentWeight = SEVERITY_WEIGHTS[item.severity] || 0;

    const highestSeverity = currentWeight > existingWeight ? item.severity : existing.severity;
    const highestConfidence = Math.max(existing.confidence, item.confidence);
    const primaryDescription =
      currentWeight > existingWeight ? item.description : existing.description;
    const primaryLocation = existing.location || item.location;
    const primarySnippet = existing.snippet || item.snippet;

    const mergedRawData = {
      ...(existing.rawData || {}),
      ...(item.rawData || {}),
    };

    dedupMap.set(item.dedupKey, {
      ...existing,
      id: existing.id,
      scanner: existing.scanner,
      category: existing.category,
      severity: highestSeverity,
      confidence: highestConfidence,
      description: primaryDescription,
      location: primaryLocation,
      snippet: primarySnippet,
      sources: mergedSources,
      rawData: mergedRawData,
    });
  }

  return Array.from(dedupMap.values());
}

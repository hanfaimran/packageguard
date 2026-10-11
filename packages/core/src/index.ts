export const PACKAGEGUARD_VERSION = '0.1.0';

export function createEmptyEvidence(id: string, scanner: string): import('./types.js').Evidence {
  return {
    id,
    scanner,
    category: 'metadata',
    severity: 'INFO',
    confidence: 1.0,
    description: '',
    dedupKey: `${scanner}:${id}`,
  };
}

export * from './types.js';

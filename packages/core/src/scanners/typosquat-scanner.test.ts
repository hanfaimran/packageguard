import { describe, it, expect } from 'vitest';
import {
  TyposquatScanner,
  levenshteinDistance,
  isCharacterSwap,
  isCharacterRepeat,
  hasHomoglyphMatch,
} from './typosquat-scanner.js';
import type { ScanContext } from '../types.js';

describe('TyposquatScanner', () => {
  it('computes distance, swaps, repeats and homoglyphs', () => {
    expect(levenshteinDistance('lodahs', 'lodash')).toBe(2);
    expect(isCharacterSwap('lodahs', 'lodash')).toBe(true);
    expect(isCharacterRepeat('looodash', 'lodash')).toBe(true);
    expect(hasHomoglyphMatch('l0dash', 'lodash')).toBe(true);
  });

  it('flags "lodahs" as typosquat of lodash and explains why', async () => {
    const scanner = new TyposquatScanner({
      version: '1.0.0',
      source: 'test',
      packages: ['lodash'],
    });

    const ctx: ScanContext = {
      packageName: 'lodahs',
      ecosystem: 'npm',
      version: '1.0.0',
    };

    const evidence = await scanner.collect(ctx);
    expect(evidence.length).toBe(1);
    expect(evidence[0].category).toBe('typosquat');
    expect(evidence[0].description).toContain('adjacent character swap from \'lodash\'');
    // Without corroborating signals, confidence remains low (0.5) and severity LOW
    expect(evidence[0].confidence).toBe(0.5);
    expect(evidence[0].severity).toBe('LOW');
  });

  it('raises confidence and severity when corroborating signals exist', async () => {
    const scanner = new TyposquatScanner({
      version: '1.0.0',
      source: 'test',
      packages: ['lodash'],
    });

    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    const ctx: ScanContext = {
      packageName: 'lodahs',
      ecosystem: 'npm',
      version: '1.0.0',
      registryMetadata: {
        time: { created: tenDaysAgo },
        versions: {
          '1.0.0': {
            scripts: { postinstall: 'curl evil.invalid' },
          },
        },
      },
    };

    const evidence = await scanner.collect(ctx);
    expect(evidence.length).toBe(1);
    expect(evidence[0].confidence).toBe(0.9);
    expect(evidence[0].severity).toBe('HIGH');
    expect(evidence[0].description).toContain('contains lifecycle install script');
  });

  it('does not flag authentic package name as squatting on itself', async () => {
    const scanner = new TyposquatScanner({
      version: '1.0.0',
      source: 'test',
      packages: ['lodash'],
    });

    const ctx: ScanContext = {
      packageName: 'lodash',
      ecosystem: 'npm',
      version: '4.17.21',
    };

    const evidence = await scanner.collect(ctx);
    expect(evidence.length).toBe(0);
  });
});

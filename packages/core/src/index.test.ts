import { describe, it, expect } from 'vitest';
import { placeholder } from './index.js';

describe('core placeholder', () => {
  it('should export placeholder', () => {
    expect(placeholder).toBe(true);
  });
});

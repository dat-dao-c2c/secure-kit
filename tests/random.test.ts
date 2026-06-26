import { describe, it, expect } from 'vitest';
import { generateBytes, generateHex, generateUUID, generateInt } from '../src/index.js';

describe('Random', () => {
  it('should generate bytes', () => {
    const size = 16;
    const result = generateBytes(size);
    expect(result.length).toBe(size);
  });

  it('should generate hex string', () => {
    const size = 16;
    const result = generateHex(size);
    expect(result.length).toBe(size * 2);
    expect(/^[0-9a-f]+$/.test(result)).toBe(true);
  });

  it('should generate UUID', () => {
    const result = generateUUID();
    expect(result).toBeDefined();
    expect(result.split('-').length).toBe(5);
  });

  it('should generate random int', () => {
    const min = 1;
    const max = 100;
    const result = generateInt(min, max);
    expect(result).toBeGreaterThanOrEqual(min);
    expect(result).toBeLessThan(max);
  });
});

import { describe, it, expect } from 'vitest';
import {
  generateBytes,
  generateHex,
  generateUUID,
  generateInt,
  generateSecureString,
  generateSecureStrings,
} from '../src/index.js';

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

  it('should generate a secure string of the requested length', () => {
    const length = 20;
    const result = generateSecureString(length);
    expect(result.length).toBe(length);
    expect(/^[A-Za-z0-9]+$/.test(result)).toBe(true);
  });

  it('should restrict the secure string to the requested character sets', () => {
    const result = generateSecureString(50, {
      letters: false,
      numbers: true,
      specialCharacters: false,
    });
    expect(/^[0-9]+$/.test(result)).toBe(true);
  });

  it('should include special characters when requested', () => {
    const result = generateSecureString(200, {
      letters: false,
      numbers: false,
      specialCharacters: true,
    });
    expect(/^[!@#$%^&*()_+~`|}{[\]:;?><,./=-]+$/.test(result)).toBe(true);
  });

  it('should throw if no character set is enabled', () => {
    expect(() =>
      generateSecureString(10, { letters: false, numbers: false, specialCharacters: false }),
    ).toThrow();
  });

  it('should throw for a non-positive length', () => {
    expect(() => generateSecureString(0)).toThrow();
  });

  it('should generate the requested number of secure strings', () => {
    const results = generateSecureStrings(5, 12);
    expect(results.length).toBe(5);
    results.forEach((str) => expect(str.length).toBe(12));
  });
});

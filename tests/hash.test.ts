import { describe, it, expect } from 'vitest';
import { hash, hmac, hashPassword, verifyPassword } from '../src/index.js';

describe('Hashing', () => {
  it('should hash data with sha256', () => {
    const data = 'hello';
    const result = hash(data, 'sha256');
    expect(result).toBeDefined();
    expect(result.length).toBe(64);
  });

  it('should hash data with sha512', () => {
    const data = 'hello';
    const result = hash(data, 'sha512');
    expect(result).toBeDefined();
    expect(result.length).toBe(128);
  });
});

describe('HMAC', () => {
  it('should create hmac', () => {
    const data = 'hello';
    const secret = 'secret';
    const result = hmac(data, secret, 'sha256');
    expect(result).toBeDefined();
    expect(result.length).toBe(64);
  });
});

describe('Password', () => {
  it('should hash and verify password', () => {
    const password = 'mySecurePassword123';
    const hashedPassword = hashPassword(password);
    
    expect(verifyPassword(password, hashedPassword)).toBe(true);
    expect(verifyPassword('wrongPassword', hashedPassword)).toBe(false);
  });
});

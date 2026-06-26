import { describe, it, expect } from 'vitest';
import { generateAESKey, deriveKey, generateRSA, generateEd25519 } from '../src/index.js';
import { randomBytes } from 'crypto';

describe('Key Generation', () => {
  it('should generate a 32-byte AES key', () => {
    const key = generateAESKey();
    expect(key.length).toBe(32);
  });

  it('should derive a key from password', () => {
    const password = 'password';
    const salt = randomBytes(16);
    const key = deriveKey(password, salt, 32);
    expect(key.length).toBe(32);
  });

  it('should generate RSA key pair', () => {
    const { publicKey, privateKey } = generateRSA();
    expect(publicKey).toBeDefined();
    expect(privateKey).toBeDefined();
  });

  it('should generate Ed25519 key pair', () => {
    const { publicKey, privateKey } = generateEd25519();
    expect(publicKey).toBeDefined();
    expect(privateKey).toBeDefined();
  });
});

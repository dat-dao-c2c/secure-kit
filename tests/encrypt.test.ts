import { describe, it, expect } from 'vitest';
import * as cryptoKit from '../src/index.js';

describe('Symmetric Encryption', () => {
  it('should encrypt and decrypt data correctly', () => {
    const key = (cryptoKit as any).generateAESKey();
    const data = 'my sensitive data';
    
    const encrypted = (cryptoKit as any).encrypt(data, key);
    const decrypted = (cryptoKit as any).decrypt(encrypted, key);
    
    expect(decrypted).toBe(data);
  });

  it('should throw an error if key is incorrect', () => {
    const key1 = (cryptoKit as any).generateAESKey();
    const key2 = (cryptoKit as any).generateAESKey();
    const data = 'my sensitive data';
    
    const encrypted = (cryptoKit as any).encrypt(data, key1);
    
    expect(() => (cryptoKit as any).decrypt(encrypted, key2)).toThrow();
  });

  it('should produce a 12-byte IV and a 16-byte auth tag', () => {
    const key = cryptoKit.generateAESKey();
    const [iv, authTag] = cryptoKit.encrypt('data', key).split(':');
    expect(iv).toHaveLength(24);
    expect(authTag).toHaveLength(32);
  });

  it('should reject a truncated auth tag even if the remaining bytes are correct', () => {
    const key = cryptoKit.generateAESKey();
    const [iv, authTag, ciphertext] = cryptoKit.encrypt('hello', key).split(':');
    for (const tagBytes of [4, 8, 12, 15]) {
      const truncated = `${iv}:${authTag.slice(0, tagBytes * 2)}:${ciphertext}`;
      expect(() => cryptoKit.decrypt(truncated, key)).toThrow('Invalid encrypted data format.');
    }
  });

  it('should throw if the ciphertext or tag was tampered with', () => {
    const key = cryptoKit.generateAESKey();
    const [iv, authTag, ciphertext] = cryptoKit.encrypt('hello', key).split(':');
    const flip = (hex: string) => (hex[0] === '0' ? '1' : '0') + hex.slice(1);
    expect(() => cryptoKit.decrypt(`${iv}:${authTag}:${flip(ciphertext)}`, key)).toThrow();
    expect(() => cryptoKit.decrypt(`${iv}:${flip(authTag)}:${ciphertext}`, key)).toThrow();
    expect(() => cryptoKit.decrypt(`${flip(iv)}:${authTag}:${ciphertext}`, key)).toThrow();
  });

  it('should reject malformed payloads', () => {
    const key = cryptoKit.generateAESKey();
    const [iv, authTag, ciphertext] = cryptoKit.encrypt('hello', key).split(':');
    const malformed = [
      '',
      'a:b:c',
      `${iv}:${authTag}`,
      `${iv}:${authTag}:${ciphertext}:extra`,
      `${iv.slice(2)}:${authTag}:${ciphertext}`, // 11-byte IV
      `${iv}00:${authTag}:${ciphertext}`, // 13-byte IV
      `${iv}:${authTag}00:${ciphertext}`, // 17-byte tag
      `${iv}:${authTag}:${ciphertext}0`, // odd-length hex
      `${iv}:${authTag}:zz${ciphertext}`, // non-hex
      undefined as unknown as string,
    ];
    for (const payload of malformed) {
      expect(() => cryptoKit.decrypt(payload, key), String(payload)).toThrow('Invalid encrypted data format.');
    }
  });

  it('should round-trip an empty string', () => {
    const key = cryptoKit.generateAESKey();
    expect(cryptoKit.decrypt(cryptoKit.encrypt('', key), key)).toBe('');
  });

  it('should accept uppercase hex', () => {
    const key = cryptoKit.generateAESKey();
    expect(cryptoKit.decrypt(cryptoKit.encrypt('hello', key).toUpperCase(), key)).toBe('hello');
  });
});

describe('Asymmetric Encryption & Signing', () => {
  const { publicKey, privateKey } = (cryptoKit as any).generateRSA();

  it('should encrypt and decrypt data correctly', () => {
    const data = 'my sensitive data';
    
    const encrypted = (cryptoKit as any).encryptAsymmetric(data, publicKey);
    const decrypted = (cryptoKit as any).decryptAsymmetric(encrypted, privateKey);
    
    expect(decrypted).toBe(data);
  });

  it('should sign and verify data correctly', () => {
    const data = 'important document';
    
    const signature = (cryptoKit as any).sign(data, privateKey);
    const isValid = (cryptoKit as any).verify(data, signature, publicKey);
    
    expect(isValid).toBe(true);
  });

  it('should fail verification if data is tampered', () => {
    const data = 'important document';
    const tamperedData = 'important document modified';
    
    const signature = (cryptoKit as any).sign(data, privateKey);
    const isValid = (cryptoKit as any).verify(tamperedData, signature, publicKey);
    
    expect(isValid).toBe(false);
  });
});

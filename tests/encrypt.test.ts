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

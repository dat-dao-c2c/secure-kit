/**
 * Example: Symmetric Encryption (AES-256-GCM)
 * 
 * Best for encrypting data at rest. Authenticated encryption ensures
 * integrity and confidentiality.
 * 
 * Usage (after npm install secure-kit):
 * import { generateAESKey, encrypt, decrypt } from 'secure-kit';
 */
import { generateAESKey, encrypt, decrypt } from '../src/index.js';

// 1. Generate a secure 256-bit key (keep this key secret!)
const key = generateAESKey();
const data = 'Sensitive data to encrypt';

// 2. Encrypt (output is a string format: iv:authTag:encryptedData)
const encrypted = encrypt(data, key);
console.log('Encrypted data:', encrypted);

// 3. Decrypt
const decrypted = decrypt(encrypted, key);
console.log('Decrypted data:', decrypted);

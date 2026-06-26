/**
 * Example: Asymmetric Encryption (RSA-OAEP)
 * 
 * Best for securely sharing data between parties.
 * 
 * Usage (after npm install secure-kit):
 * import { generateRSA, encryptAsymmetric, decryptAsymmetric } from 'secure-kit';
 */
import { generateRSA, encryptAsymmetric, decryptAsymmetric } from '../src/index.js';

// 1. Generate key pair
const { publicKey, privateKey } = generateRSA();
const data = 'Sensitive data for RSA';

// 2. Encrypt with Public Key
const encrypted = encryptAsymmetric(data, publicKey);
console.log('Encrypted data:', encrypted);

// 3. Decrypt with Private Key
const decrypted = decryptAsymmetric(encrypted, privateKey);
console.log('Decrypted data:', decrypted);

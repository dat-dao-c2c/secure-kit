/**
 * Example: Digital Signature (RSA + SHA256)
 * 
 * Best for verifying data authenticity and integrity.
 * 
 * Usage (after npm install secure-kit):
 * import { generateRSA, sign, verify } from 'secure-kit';
 */
import { generateRSA, sign, verify } from '../src/index.js';

// 1. Generate key pair
const { publicKey, privateKey } = generateRSA();
const data = 'Document to sign';

// 2. Sign with Private Key
const signature = sign(data, privateKey);
console.log('Signature:', signature);

// 3. Verify with Public Key
const isValid = verify(data, signature, publicKey);
console.log('Is Signature Valid:', isValid);

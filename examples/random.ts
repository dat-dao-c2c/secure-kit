/**
 * Example: Secure Random Generation
 *
 * Usage (after npm install @datdm198x/secure-kit):
 * import { generateBytes, generateHex, generateUUID, generateInt } from '@datdm198x/secure-kit';
 */
import { generateBytes, generateHex, generateUUID, generateInt } from '../src/index.js';

// 1. Generate random bytes
const bytes = generateBytes(16);
console.log('Random bytes:', bytes);

// 2. Generate random hex string
const hex = generateHex(16);
console.log('Random hex:', hex);

// 3. Generate UUID
const uuid = generateUUID();
console.log('UUID:', uuid);

// 4. Generate random integer
const int = generateInt(1, 100);
console.log('Random integer (1-100):', int);

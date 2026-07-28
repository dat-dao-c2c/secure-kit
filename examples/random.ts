/**
 * Example: Secure Random Generation
 *
 * Usage (after npm install @datdm198x/secure-kit):
 * import { generateBytes, generateHex, generateUUID, generateInt, generateSecureString, generateSecureStrings } from '@datdm198x/secure-kit';
 */
import {
  generateBytes,
  generateHex,
  generateUUID,
  generateInt,
  generateSecureString,
  generateSecureStrings,
} from '../src/index.js';

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

// 5. Generate a secure string (e.g. for API keys / tokens)
const secureString = generateSecureString(20, {
  letters: true,
  numbers: true,
  specialCharacters: true,
});
console.log('Secure string:', secureString);

// 6. Generate multiple secure strings at once
const secureStrings = generateSecureStrings(5, 20, {
  letters: true,
  numbers: true,
  specialCharacters: true,
});
console.log('Secure strings:', secureStrings);

/**
 * Example: Password Hashing
 * 
 * Securely hash passwords with salt automatically included.
 * 
 * Usage (after npm install secure-kit):
 * import { hashPassword, verifyPassword } from 'secure-kit';
 */
import { hashPassword, verifyPassword } from '../src/index.js';

const password = 'mySecretPassword123';

// 1. Hash the password for storage
const hashedPassword = hashPassword(password);
console.log('Hashed Password (store this in DB):', hashedPassword);

// 2. Verify a password attempt against the stored hash
const isMatch = verifyPassword(password, hashedPassword);
console.log('Password verified successfully:', isMatch);

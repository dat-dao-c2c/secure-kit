/**
 * Example: Password Hashing (Argon2id)
 *
 * Securely hash passwords; the salt and cost parameters are stored inside the hash.
 *
 * Usage (after npm install @datdm198x/secure-kit):
 * import { hashPassword, verifyPassword, needsRehash } from '@datdm198x/secure-kit';
 */
import { hashPassword, verifyPassword, needsRehash } from '../src/index.js';

async function main(): Promise<void> {
  const password = 'mySecretPassword123';

  // 1. Hash the password for storage
  const hashedPassword = await hashPassword(password);
  console.log('Hashed Password (store this in DB):', hashedPassword);

  // 2. Verify a password attempt against the stored hash
  const isMatch = await verifyPassword(password, hashedPassword);
  console.log('Password verified successfully:', isMatch);

  // 3. After a successful login, check whether the stored hash should be upgraded
  console.log('Needs rehash:', needsRehash(hashedPassword));
}

main();

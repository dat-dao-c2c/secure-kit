import { scryptSync, randomBytes, timingSafeEqual } from 'crypto';

const KEY_LENGTH = 64;
const SALT_LENGTH = 16;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

export function hashPassword(password: string): string {
  const salt = randomBytes(SALT_LENGTH);
  const derivedKey = scryptSync(password, salt, KEY_LENGTH, SCRYPT_PARAMS);
  
  // Return combined string: salt + hash (in hex)
  return `${salt.toString('hex')}:${derivedKey.toString('hex')}`;
}

export function verifyPassword(password: string, hashedPassword: string): boolean {
  const [saltHex, hashHex] = hashedPassword.split(':');
  if (!saltHex || !hashHex) return false;

  const salt = Buffer.from(saltHex, 'hex');
  const derivedKey = scryptSync(password, salt, KEY_LENGTH, SCRYPT_PARAMS);
  const hashBuffer = Buffer.from(hashHex, 'hex');

  return timingSafeEqual(derivedKey, hashBuffer);
}

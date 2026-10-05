import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

// 'iv:authTag:ciphertext' in hex. The IV and tag lengths are fixed so a truncated tag
// (which GCM would otherwise accept, weakening forgery resistance) is rejected up front.
const PAYLOAD_FORMAT = new RegExp(
  `^([0-9a-f]{${IV_LENGTH * 2}}):([0-9a-f]{${AUTH_TAG_LENGTH * 2}}):((?:[0-9a-f]{2})*)$`,
  'i',
);

/**
 * Encrypts data using AES-256-GCM.
 * Returns a string formatted as 'iv:authTag:encryptedData' in hex.
 */
export function encrypt(data: string, key: Buffer): string {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

  const encrypted = cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
  const authTag = cipher.getAuthTag();

  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypts data using AES-256-GCM.
 * Input should be formatted as 'iv:authTag:encryptedData' in hex, with a 12-byte IV
 * and a 16-byte authentication tag. Throws if the format is invalid, the key is wrong,
 * or the data was tampered with.
 */
export function decrypt(encryptedData: string, key: Buffer): string {
  const match = typeof encryptedData === 'string' ? PAYLOAD_FORMAT.exec(encryptedData) : null;
  if (!match) {
    throw new Error('Invalid encrypted data format.');
  }
  const [, ivHex, authTagHex, encrypted] = match;

  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

  decipher.setAuthTag(authTag);

  return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
}

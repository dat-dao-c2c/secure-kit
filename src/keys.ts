import { 
  randomBytes, 
  scryptSync, 
  generateKeyPairSync, 
  KeyPairSyncResult,
  KeyObject 
} from 'crypto';

/**
 * Generates a cryptographically strong 256-bit (32-byte) AES key.
 */
export function generateAESKey(): Buffer {
  return randomBytes(32);
}

/**
 * Derives a key from a password using scrypt.
 * @param password The input password.
 * @param salt A random salt.
 * @param keyLength The desired key length in bytes.
 */
export function deriveKey(password: string, salt: Buffer, keyLength: number = 32): Buffer {
  return scryptSync(password, salt, keyLength);
}

/**
 * Generates an RSA key pair (4096-bit).
 */
export function generateRSA(): KeyPairSyncResult<KeyObject, KeyObject> {
  return generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

/**
 * Generates an Ed25519 key pair.
 */
export function generateEd25519(): KeyPairSyncResult<KeyObject, KeyObject> {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

import { createHash, createHmac } from 'crypto';

/**
 * Performs a one-way hash on the provided data.
 * 
 * **Common Usecase:**
 * - Data Integrity: Verify files or data have not been tampered with.
 * - Data Mapping: Generate consistent, unique identifiers without exposing the original data.
 * 
 * @param data The input string to hash.
 * @param algorithm The algorithm to use: 'sha256' | 'sha512'.
 * @returns The hashed string in hex format.
 */
export function hash(data: string, algorithm: 'sha256' | 'sha512' = 'sha256'): string {
  return createHash(algorithm).update(data).digest('hex');
}

/**
 * Creates an HMAC (Hash-based Message Authentication Code).
 * 
 * **Common Usecase:**
 * - API Request Signing: Verify that an API request originated from a trusted source.
 * 
 * @param data The input data.
 * @param secret The secret key.
 * @param algorithm The algorithm to use: 'sha256' | 'sha512'.
 * @returns The HMAC string in hex format.
 */
export function hmac(data: string, secret: string, algorithm: 'sha256' | 'sha512' = 'sha256'): string {
  return createHmac(algorithm, secret).update(data).digest('hex');
}

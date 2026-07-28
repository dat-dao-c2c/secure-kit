import { randomBytes, randomUUID, randomInt } from 'crypto';

export function generateBytes(size: number): Buffer {
  return randomBytes(size);
}

export function generateHex(size: number): string {
  return randomBytes(size).toString('hex');
}

export function generateUUID(): string {
  return randomUUID();
}

export function generateInt(min: number, max: number): number {
  return randomInt(min, max);
}

const LETTER_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const NUMBER_CHARS = '0123456789';
const SPECIAL_CHARS = '!@#$%^&*()_+~`|}{[]:;?><,./-=';

export interface GenerateSecureStringOptions {
  letters?: boolean;
  numbers?: boolean;
  specialCharacters?: boolean;
}

/**
 * Generates a single cryptographically secure random string built from the
 * requested character sets. At least one of letters/numbers/specialCharacters
 * must be enabled.
 */
export function generateSecureString(
  length: number,
  options: GenerateSecureStringOptions = {},
): string {
  const { letters = true, numbers = true, specialCharacters = false } = options;

  if (!Number.isInteger(length) || length <= 0) {
    throw new Error('length must be a positive integer.');
  }

  let pool = '';
  if (letters) pool += LETTER_CHARS;
  if (numbers) pool += NUMBER_CHARS;
  if (specialCharacters) pool += SPECIAL_CHARS;

  if (pool.length === 0) {
    throw new Error(
      'At least one character set (letters, numbers, specialCharacters) must be enabled.',
    );
  }

  let result = '';
  for (let i = 0; i < length; i++) {
    // randomInt is uniform over [0, pool.length) — avoids the modulo bias
    // you'd get from byte % pool.length.
    result += pool[randomInt(pool.length)];
  }
  return result;
}

/**
 * Generates multiple cryptographically secure random strings. Each string
 * is generated independently via generateSecureString.
 */
export function generateSecureStrings(
  count: number,
  length: number,
  options: GenerateSecureStringOptions = {},
): string[] {
  if (!Number.isInteger(count) || count <= 0) {
    throw new Error('count must be a positive integer.');
  }
  return Array.from({ length: count }, () => generateSecureString(length, options));
}

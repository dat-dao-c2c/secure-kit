import { describe, it, expect } from 'vitest';
import { argon2Sync, randomBytes, scryptSync } from 'crypto';
import {
  hashPassword,
  hashPasswordSync,
  verifyPassword,
  verifyPasswordSync,
  isPasswordHash,
  needsRehash,
  MAX_PASSWORD_BYTES,
} from '../src/index.js';

const PHC = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;
// Cheapest parameters the creation API accepts, to keep tests fast.
const FAST = { memory: 19456, passes: 2, parallelism: 1 };

const b64 = (buffer: Buffer) => buffer.toString('base64').replace(/=+$/, '');

/** A 1.x-format scrypt hash, as stored by secure-kit before the Argon2id migration. */
function legacyHash(password: string): string {
  const salt = randomBytes(16);
  return `${salt.toString('hex')}:${scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex')}`;
}

/** An Argon2id hash built directly with node:crypto, as another implementation would produce. */
function foreignArgon2Hash(password: string, memory: number, passes: number, parallelism: number): string {
  const salt = randomBytes(16);
  const tag = argon2Sync('argon2id', { message: password, nonce: salt, memory, passes, parallelism, tagLength: 32 });
  return `$argon2id$v=19$m=${memory},t=${passes},p=${parallelism}$${b64(salt)}$${b64(tag)}`;
}

describe('hashPassword / verifyPassword', () => {
  it('hashes with Argon2id defaults (64 MiB, t=3, p=4) in PHC format', async () => {
    const stored = await hashPassword('mySecurePassword123');
    const [, m, t, p, salt, tag] = PHC.exec(stored)!;
    expect([m, t, p]).toEqual(['65536', '3', '4']);
    expect(Buffer.from(salt, 'base64')).toHaveLength(16);
    expect(Buffer.from(tag, 'base64')).toHaveLength(32);

    expect(await verifyPassword('mySecurePassword123', stored)).toBe(true);
    expect(await verifyPassword('wrongPassword', stored)).toBe(false);
  });

  it('uses a fresh salt for every hash', async () => {
    const [a, b] = await Promise.all([hashPassword('same', FAST), hashPassword('same', FAST)]);
    expect(a).not.toBe(b);
  });

  it('honours custom cost options and records them in the hash', async () => {
    const stored = await hashPassword('pw', { memory: 32768, passes: 2, parallelism: 2 });
    expect(stored).toContain('$m=32768,t=2,p=2$');
    expect(await verifyPassword('pw', stored)).toBe(true);
  });

  it('sync and async variants are interchangeable', async () => {
    const stored = hashPasswordSync('pw', FAST);
    expect(await verifyPassword('pw', stored)).toBe(true);
    expect(verifyPasswordSync('pw', await hashPassword('pw', FAST))).toBe(true);
    expect(verifyPasswordSync('nope', stored)).toBe(false);
  });

  it('normalizes Unicode (NFKC) so equivalent inputs match', async () => {
    const composed = 'café'; // é as one code point
    const decomposed = 'café'; // e + combining acute accent
    const stored = await hashPassword(composed, FAST);
    expect(await verifyPassword(decomposed, stored)).toBe(true);
  });

  it('rejects invalid passwords when hashing', async () => {
    await expect(hashPassword('')).rejects.toThrow(RangeError);
    await expect(hashPassword('a'.repeat(MAX_PASSWORD_BYTES + 1))).rejects.toThrow(RangeError);
    await expect(hashPassword(42 as unknown as string)).rejects.toThrow(TypeError);
    expect(() => hashPasswordSync('')).toThrow(RangeError);
  });

  it('rejects cost options below the OWASP minimum or above the safety cap', async () => {
    await expect(hashPassword('pw', { memory: 4096 })).rejects.toThrow(/memory/);
    await expect(hashPassword('pw', { passes: 1 })).rejects.toThrow(/passes/);
    await expect(hashPassword('pw', { parallelism: 0 })).rejects.toThrow(/parallelism/);
    await expect(hashPassword('pw', { memory: 1.5 as number })).rejects.toThrow(/memory/);
  });

  it('accepts a password at exactly the byte limit, and returns false (not throws) above it', async () => {
    const atLimit = 'a'.repeat(MAX_PASSWORD_BYTES);
    const stored = await hashPassword(atLimit, FAST);
    expect(await verifyPassword(atLimit, stored)).toBe(true);
    expect(await verifyPassword(`${atLimit}a`, stored)).toBe(false);
  });

  it('returns false instead of throwing for malformed hashes', async () => {
    const valid = await hashPassword('pw', FAST);
    const malformed = [
      '',
      'abcd:1234',
      'not-a-hash',
      valid.replace('argon2id', 'argon2i'),
      valid.replace('v=19', 'v=16'),
      valid.slice(0, -30), // truncated tag (< 16 bytes)
      `${valid}$extra`,
      valid.replace('m=19456', 'm=999999999'), // above memory cap
      valid.replace('t=2', 't=1000'), // above passes cap
      null as unknown as string,
    ];
    for (const stored of malformed) {
      expect(await verifyPassword('pw', stored), String(stored)).toBe(false);
      expect(verifyPasswordSync('pw', stored), String(stored)).toBe(false);
      expect(isPasswordHash(stored), String(stored)).toBe(false);
    }
  });

  it('returns false for a non-string password against a valid hash', async () => {
    const stored = await hashPassword('pw', FAST);
    expect(await verifyPassword(undefined as unknown as string, stored)).toBe(false);
    expect(await verifyPassword('', stored)).toBe(false);
  });

  it('verifies Argon2id hashes from other implementations, including weaker parameters', async () => {
    const weak = foreignArgon2Hash('pw', 4096, 1, 1);
    expect(isPasswordHash(weak)).toBe(true);
    expect(await verifyPassword('pw', weak)).toBe(true);
    expect(await verifyPassword('nope', weak)).toBe(false);
  });
});

describe('legacy scrypt hashes (secure-kit 1.x)', () => {
  it('still verify, without Unicode normalization', async () => {
    const stored = legacyHash('oldPassword');
    expect(isPasswordHash(stored)).toBe(true);
    expect(await verifyPassword('oldPassword', stored)).toBe(true);
    expect(verifyPasswordSync('oldPassword', stored)).toBe(true);
    expect(await verifyPassword('wrong', stored)).toBe(false);

    const decomposed = legacyHash('café');
    expect(await verifyPassword('café', decomposed)).toBe(true);
  });

  it('are always flagged for rehash', () => {
    expect(needsRehash(legacyHash('pw'))).toBe(true);
  });
});

describe('needsRehash', () => {
  it('is false for a hash made with the target parameters', async () => {
    expect(needsRehash(await hashPassword('pw'))).toBe(false);
    expect(needsRehash(await hashPassword('pw', FAST), FAST)).toBe(false);
  });

  it('is true when parameters differ from the target', async () => {
    const stored = await hashPassword('pw', FAST);
    expect(needsRehash(stored)).toBe(true);
    expect(needsRehash(stored, { ...FAST, memory: 32768 })).toBe(true);
    expect(needsRehash(foreignArgon2Hash('pw', 4096, 1, 1))).toBe(true);
  });

  it('is true for malformed input', () => {
    expect(needsRehash('garbage')).toBe(true);
    expect(needsRehash(undefined as unknown as string)).toBe(true);
  });
});

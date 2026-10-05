import { argon2, argon2Sync, randomBytes, scrypt, scryptSync, timingSafeEqual } from 'crypto';

/**
 * Argon2id cost parameters. Defaults follow RFC 9106 / OWASP guidance:
 * 64 MiB memory, 3 passes, 4 lanes.
 */
export interface PasswordHashOptions {
  /** Memory cost in KiB. Default 65536 (64 MiB). Minimum 19456 (19 MiB, OWASP floor). */
  memory?: number;
  /** Number of passes (iterations). Default 3. Minimum 2. */
  passes?: number;
  /** Degree of parallelism (lanes). Default 4. */
  parallelism?: number;
}

type Argon2Params = Required<PasswordHashOptions>;

interface ParsedArgon2Hash extends Argon2Params {
  salt: Buffer;
  hash: Buffer;
}

interface ParsedScryptHash {
  salt: Buffer;
  hash: Buffer;
}

const DEFAULT_PARAMS: Argon2Params = { memory: 65536, passes: 3, parallelism: 4 };
const SALT_LENGTH = 16;
const TAG_LENGTH = 32;

/** Upper bound on the UTF-8 size of a password, to bound work on untrusted input. */
export const MAX_PASSWORD_BYTES = 1024;

// Bounds for parameters used to create new hashes (lower bounds = OWASP minimum).
const LIMITS = {
  memory: { min: 19456, max: 4 * 1024 * 1024 }, // 19 MiB .. 4 GiB
  passes: { min: 2, max: 64 },
  parallelism: { min: 1, max: 64 },
};

// Bounds for parameters parsed from stored hashes. Weaker hashes from other systems still
// verify (and needsRehash flags them); the upper bounds stop a crafted hash from making
// verification allocate unbounded memory or CPU.
const PARSE_LIMITS = {
  memory: { min: 8, max: LIMITS.memory.max },
  passes: { min: 1, max: LIMITS.passes.max },
  parallelism: { min: 1, max: LIMITS.parallelism.max },
  saltBytes: { min: 8, max: 64 },
  tagBytes: { min: 16, max: 64 },
};

const ARGON2_VERSION = 19; // 0x13, the only version Node implements
const ARGON2_PHC = /^\$argon2id\$v=19\$m=(\d{1,10}),t=(\d{1,10}),p=(\d{1,10})\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;

// Legacy format produced by secure-kit 1.x: scrypt(N=16384, r=8, p=1), `saltHex:hashHex`.
const LEGACY_SCRYPT = /^([0-9a-f]{32}):([0-9a-f]{128})$/i;
const LEGACY_SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };
const LEGACY_KEY_LENGTH = 64;

// ---------- helpers ----------

function inRange(value: number, { min, max }: { min: number; max: number }): boolean {
  return Number.isSafeInteger(value) && value >= min && value <= max;
}

function resolveParams(options: PasswordHashOptions = {}): Argon2Params {
  const params = { ...DEFAULT_PARAMS, ...options };
  for (const name of ['memory', 'passes', 'parallelism'] as const) {
    if (!inRange(params[name], LIMITS[name])) {
      const { min, max } = LIMITS[name];
      throw new RangeError(`${name} must be an integer between ${min} and ${max}`);
    }
  }
  if (params.memory < 8 * params.parallelism) {
    throw new RangeError('memory must be at least 8 * parallelism KiB');
  }
  return params;
}

/** NFKC-normalizes the password (NIST SP 800-63B) and enforces type and size limits. */
function preparePassword(password: string): string {
  if (typeof password !== 'string') throw new TypeError('password must be a string');
  if (password.length === 0) throw new RangeError('password must not be empty');
  const normalized = password.normalize('NFKC');
  if (Buffer.byteLength(normalized, 'utf8') > MAX_PASSWORD_BYTES) {
    throw new RangeError(`password must be at most ${MAX_PASSWORD_BYTES} bytes`);
  }
  return normalized;
}

/** Like preparePassword, but returns undefined instead of throwing (for verification paths). */
function tryPreparePassword(password: string): string | undefined {
  try {
    return preparePassword(password);
  } catch {
    return undefined;
  }
}

function toB64(buffer: Buffer): string {
  return buffer.toString('base64').replace(/=+$/, '');
}

function formatArgon2Hash(params: Argon2Params, salt: Buffer, hash: Buffer): string {
  const { memory, passes, parallelism } = params;
  return `$argon2id$v=${ARGON2_VERSION}$m=${memory},t=${passes},p=${parallelism}$${toB64(salt)}$${toB64(hash)}`;
}

function parseArgon2Hash(stored: string): ParsedArgon2Hash | undefined {
  const match = ARGON2_PHC.exec(stored);
  if (!match) return undefined;
  const [, m, t, p, saltB64, hashB64] = match;
  const parsed: ParsedArgon2Hash = {
    memory: Number(m),
    passes: Number(t),
    parallelism: Number(p),
    salt: Buffer.from(saltB64, 'base64'),
    hash: Buffer.from(hashB64, 'base64'),
  };
  const valid =
    inRange(parsed.memory, PARSE_LIMITS.memory) &&
    inRange(parsed.passes, PARSE_LIMITS.passes) &&
    inRange(parsed.parallelism, PARSE_LIMITS.parallelism) &&
    parsed.memory >= 8 * parsed.parallelism &&
    inRange(parsed.salt.length, PARSE_LIMITS.saltBytes) &&
    inRange(parsed.hash.length, PARSE_LIMITS.tagBytes);
  return valid ? parsed : undefined;
}

function parseLegacyScryptHash(stored: string): ParsedScryptHash | undefined {
  const match = LEGACY_SCRYPT.exec(stored);
  if (!match) return undefined;
  return { salt: Buffer.from(match[1], 'hex'), hash: Buffer.from(match[2], 'hex') };
}

function argon2Input(password: string, params: Argon2Params, salt: Buffer, tagLength: number) {
  const { memory, passes, parallelism } = params;
  return { message: password, nonce: salt, tagLength, memory, passes, parallelism };
}

function argon2Async(...args: Parameters<typeof argon2Sync>): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    argon2(...args, (err, derivedKey) => (err ? reject(err) : resolve(derivedKey)));
  });
}

function scryptAsync(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, LEGACY_KEY_LENGTH, LEGACY_SCRYPT_PARAMS, (err, derivedKey) =>
      err ? reject(err) : resolve(derivedKey),
    );
  });
}

// ---------- public API ----------

/**
 * Hashes a password with Argon2id and returns a self-describing PHC string:
 * `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`.
 *
 * Throws TypeError/RangeError for a non-string, empty, or over-long password, or invalid options.
 */
export async function hashPassword(password: string, options?: PasswordHashOptions): Promise<string> {
  const prepared = preparePassword(password);
  const params = resolveParams(options);
  const salt = randomBytes(SALT_LENGTH);
  const hash = await argon2Async('argon2id', argon2Input(prepared, params, salt, TAG_LENGTH));
  return formatArgon2Hash(params, salt, hash);
}

/** Synchronous variant of {@link hashPassword}. Blocks the event loop; prefer the async version in servers. */
export function hashPasswordSync(password: string, options?: PasswordHashOptions): string {
  const prepared = preparePassword(password);
  const params = resolveParams(options);
  const salt = randomBytes(SALT_LENGTH);
  const hash = argon2Sync('argon2id', argon2Input(prepared, params, salt, TAG_LENGTH));
  return formatArgon2Hash(params, salt, hash);
}

/**
 * Checks a password against a stored hash in constant time.
 *
 * Accepts Argon2id PHC strings and legacy secure-kit 1.x scrypt hashes (`salt:hash`).
 * Returns false — never throws — for a wrong password or a malformed/unsupported hash.
 */
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  if (typeof storedHash !== 'string') return false;

  const argon = parseArgon2Hash(storedHash);
  if (argon) {
    const prepared = tryPreparePassword(password);
    if (prepared === undefined) return false;
    const derived = await argon2Async('argon2id', argon2Input(prepared, argon, argon.salt, argon.hash.length));
    return timingSafeEqual(derived, argon.hash);
  }

  const legacy = parseLegacyScryptHash(storedHash);
  if (legacy) {
    // Legacy hashes were computed over the raw (un-normalized) password.
    if (typeof password !== 'string' || Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) return false;
    const derived = await scryptAsync(password, legacy.salt);
    return timingSafeEqual(derived, legacy.hash);
  }

  return false;
}

/** Synchronous variant of {@link verifyPassword}. Blocks the event loop; prefer the async version in servers. */
export function verifyPasswordSync(password: string, storedHash: string): boolean {
  if (typeof storedHash !== 'string') return false;

  const argon = parseArgon2Hash(storedHash);
  if (argon) {
    const prepared = tryPreparePassword(password);
    if (prepared === undefined) return false;
    const derived = argon2Sync('argon2id', argon2Input(prepared, argon, argon.salt, argon.hash.length));
    return timingSafeEqual(derived, argon.hash);
  }

  const legacy = parseLegacyScryptHash(storedHash);
  if (legacy) {
    if (typeof password !== 'string' || Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) return false;
    const derived = scryptSync(password, legacy.salt, LEGACY_KEY_LENGTH, LEGACY_SCRYPT_PARAMS);
    return timingSafeEqual(derived, legacy.hash);
  }

  return false;
}

/** True if the string is a hash that {@link verifyPassword} can check (Argon2id PHC or legacy scrypt). */
export function isPasswordHash(storedHash: string): boolean {
  if (typeof storedHash !== 'string') return false;
  return parseArgon2Hash(storedHash) !== undefined || parseLegacyScryptHash(storedHash) !== undefined;
}

/**
 * True if the stored hash should be replaced after the next successful login: it is a legacy
 * scrypt hash, malformed, or its Argon2id parameters differ from the target `options`.
 *
 * @example
 * if (await verifyPassword(pw, user.passwordHash) && needsRehash(user.passwordHash)) {
 *   await saveHash(user.id, await hashPassword(pw));
 * }
 */
export function needsRehash(storedHash: string, options?: PasswordHashOptions): boolean {
  const target = resolveParams(options);
  const argon = typeof storedHash === 'string' ? parseArgon2Hash(storedHash) : undefined;
  if (!argon) return true;
  return (
    argon.memory !== target.memory ||
    argon.passes !== target.passes ||
    argon.parallelism !== target.parallelism ||
    argon.salt.length < SALT_LENGTH ||
    argon.hash.length < TAG_LENGTH
  );
}

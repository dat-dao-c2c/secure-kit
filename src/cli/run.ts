import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { parseArgs } from 'util';
import { createPrivateKey, createPublicKey, timingSafeEqual, KeyObject } from 'crypto';
import {
  hash,
  hmac,
  hashPasswordSync,
  verifyPasswordSync,
  isPasswordHash,
  MAX_PASSWORD_BYTES,
  encrypt,
  decrypt,
  encryptAsymmetric,
  decryptAsymmetric,
  sign,
  verify,
  generateAESKey,
  generateRSA,
  generateHex,
  generateUUID,
  generateInt,
  generateSecureStrings,
} from '../index.js';

export const EXIT_OK = 0;
/** Verification failed, or decryption failed (wrong key / tampered data). */
export const EXIT_FAILED = 1;
/** Invalid usage: unknown command, bad option, missing input or secret. */
export const EXIT_USAGE = 2;

export interface CliIO {
  /** Returns all of stdin, or undefined when stdin is an interactive terminal. */
  readStdin(): string | undefined;
  stdout(text: string): void;
  stderr(text: string): void;
  env: NodeJS.ProcessEnv;
}

class UsageError extends Error {}

type Values = Record<string, string | boolean | undefined>;

interface CommandContext {
  values: Values;
  positionals: string[];
  io: CliIO;
  /** Name the user invoked (secret-kit or secure-kit), used in messages. */
  prog: string;
}

interface OptionSpec {
  type: 'string' | 'boolean';
  short?: string;
}

interface Command {
  summary: string;
  usage: string;
  options: Record<string, OptionSpec>;
  run(ctx: CommandContext): number;
}

const HASH_ALGORITHMS = ['sha256', 'sha512'] as const;
type HashAlgorithm = (typeof HASH_ALGORITHMS)[number];

const RAW_OPTION: Record<string, OptionSpec> = { raw: { type: 'boolean' } };
const QUIET_OPTION: Record<string, OptionSpec> = { quiet: { type: 'boolean', short: 'q' } };
const ALGORITHM_OPTION: Record<string, OptionSpec> = { algorithm: { type: 'string', short: 'a' } };
const SECRET_OPTIONS: Record<string, OptionSpec> = {
  'secret-env': { type: 'string' },
  'secret-file': { type: 'string' },
};
const KEY_OPTIONS: Record<string, OptionSpec> = {
  'key-env': { type: 'string' },
  'key-file': { type: 'string' },
};

// ---------- helpers ----------

function writeLine(io: CliIO, text: string): void {
  io.stdout(text.endsWith('\n') ? text : `${text}\n`);
}

function stringOpt(values: Values, name: string): string | undefined {
  const value = values[name];
  return typeof value === 'string' ? value : undefined;
}

function requireOpt(values: Values, name: string): string {
  const value = stringOpt(values, name);
  if (value === undefined || value === '') throw new UsageError(`missing required option --${name}`);
  return value;
}

function stripTrailingNewline(text: string): string {
  return text.replace(/\r?\n$/, '');
}

function readStdin(io: CliIO, raw: boolean): string {
  const input = io.readStdin();
  if (input === undefined) {
    throw new UsageError('no input: pass it as an argument or pipe it on stdin');
  }
  return raw ? input : stripTrailingNewline(input);
}

/** Input comes from the single positional argument, or stdin when it is absent or "-". */
function readInput({ values, positionals, io }: CommandContext): string {
  if (positionals.length > 1) throw new UsageError('too many arguments (quote input containing spaces)');
  const [arg] = positionals;
  if (arg !== undefined && arg !== '-') return arg;
  return readStdin(io, values.raw === true);
}

/** Sensitive input (passwords) is only accepted on stdin, never as an argument. */
function readStdinOnly(ctx: CommandContext, label: string): string {
  if (ctx.positionals.length > 0) {
    throw new UsageError(`${label} must be piped on stdin, not passed as an argument`);
  }
  return readStdin(ctx.io, ctx.values.raw === true);
}

function readTextFile(path: string, label: string): string {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    throw new UsageError(`cannot read ${label} file: ${path}`);
  }
}

/** Reads a secret from exactly one of --<prefix>-env or --<prefix>-file. */
function readSecret(ctx: CommandContext, prefix: 'secret' | 'key'): string {
  const envName = stringOpt(ctx.values, `${prefix}-env`);
  const filePath = stringOpt(ctx.values, `${prefix}-file`);

  if ((envName === undefined) === (filePath === undefined)) {
    throw new UsageError(`provide exactly one of --${prefix}-env or --${prefix}-file`);
  }

  if (envName !== undefined) {
    const value = ctx.io.env[envName];
    if (!value) throw new UsageError(`environment variable ${envName} is empty or not set`);
    return value;
  }

  const value = stripTrailingNewline(readTextFile(filePath as string, prefix));
  if (!value) throw new UsageError(`${prefix} file is empty: ${filePath}`);
  return value;
}

function readAesKey(ctx: CommandContext): Buffer {
  const hex = readSecret(ctx, 'key').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new UsageError(`AES key must be 64 hex characters (32 bytes); generate one with: ${ctx.prog} keygen aes`);
  }
  return Buffer.from(hex, 'hex');
}

function readKeyObject(ctx: CommandContext, option: 'private-key' | 'public-key'): KeyObject {
  const path = requireOpt(ctx.values, option);
  const pem = readTextFile(path, option);
  try {
    return option === 'private-key' ? createPrivateKey(pem) : createPublicKey(pem);
  } catch {
    throw new UsageError(`invalid ${option.replace('-', ' ')} file: ${path}`);
  }
}

function readAlgorithm(values: Values): HashAlgorithm {
  const algorithm = stringOpt(values, 'algorithm') ?? 'sha256';
  if (!(HASH_ALGORITHMS as readonly string[]).includes(algorithm)) {
    throw new UsageError(`unsupported algorithm "${algorithm}" (use: ${HASH_ALGORITHMS.join(', ')})`);
  }
  return algorithm as HashAlgorithm;
}

function parseIntArg(value: string | undefined, name: string, fallback?: number): number {
  if (value === undefined) {
    if (fallback === undefined) throw new UsageError(`missing required argument <${name}>`);
    return fallback;
  }
  const parsed = /^-?\d+$/.test(value) ? Number(value) : NaN;
  if (!Number.isSafeInteger(parsed)) throw new UsageError(`<${name}> must be an integer, got "${value}"`);
  return parsed;
}

function expectPositionals(positionals: string[], max: number): void {
  if (positionals.length > max) throw new UsageError(`unexpected argument "${positionals[max]}"`);
}

function reportVerification(io: CliIO, values: Values, isValid: boolean): number {
  if (values.quiet !== true) {
    if (isValid) writeLine(io, 'valid');
    else io.stderr('invalid\n');
  }
  return isValid ? EXIT_OK : EXIT_FAILED;
}

/** Constant-time comparison of two hex strings; false on any length mismatch. */
function hexEqual(expectedHex: string, receivedHex: string): boolean {
  const expected = Buffer.from(expectedHex, 'hex');
  const received = Buffer.from(receivedHex, 'hex');
  return received.length === expected.length && timingSafeEqual(received, expected);
}

// ---------- commands ----------

const COMMANDS: Record<string, Command> = {
  hash: {
    summary: 'Hash text with SHA-256 or SHA-512',
    usage: 'hash [-a sha256|sha512] [--raw] [TEXT|-]',
    options: { ...ALGORITHM_OPTION, ...RAW_OPTION },
    run(ctx) {
      writeLine(ctx.io, hash(readInput(ctx), readAlgorithm(ctx.values)));
      return EXIT_OK;
    },
  },

  hmac: {
    summary: 'Create an HMAC signature of text',
    usage: 'hmac (--secret-env VAR | --secret-file PATH) [-a sha256|sha512] [--raw] [TEXT|-]',
    options: { ...SECRET_OPTIONS, ...ALGORITHM_OPTION, ...RAW_OPTION },
    run(ctx) {
      const secret = readSecret(ctx, 'secret');
      writeLine(ctx.io, hmac(readInput(ctx), secret, readAlgorithm(ctx.values)));
      return EXIT_OK;
    },
  },

  'hmac-verify': {
    summary: 'Verify an HMAC signature (exit 0 = valid, 1 = invalid)',
    usage: 'hmac-verify --signature HEX (--secret-env VAR | --secret-file PATH) [-a sha256|sha512] [-q] [--raw] [TEXT|-]',
    options: { signature: { type: 'string' }, ...SECRET_OPTIONS, ...ALGORITHM_OPTION, ...QUIET_OPTION, ...RAW_OPTION },
    run(ctx) {
      const signature = requireOpt(ctx.values, 'signature');
      const secret = readSecret(ctx, 'secret');
      const expected = hmac(readInput(ctx), secret, readAlgorithm(ctx.values));
      return reportVerification(ctx.io, ctx.values, hexEqual(expected, signature));
    },
  },

  'password-hash': {
    summary: 'Hash a password read from stdin (Argon2id)',
    usage: 'password-hash [--raw] < password',
    options: { ...RAW_OPTION },
    run(ctx) {
      const password = readStdinOnly(ctx, 'password');
      if (!password) throw new UsageError('password is empty');
      if (Buffer.byteLength(password.normalize('NFKC'), 'utf8') > MAX_PASSWORD_BYTES) {
        throw new UsageError(`password is longer than ${MAX_PASSWORD_BYTES} bytes`);
      }
      writeLine(ctx.io, hashPasswordSync(password));
      return EXIT_OK;
    },
  },

  'password-verify': {
    summary: 'Verify a password from stdin against a hash (exit 0 = match, 1 = no match)',
    usage: 'password-verify --hash HASH [-q] [--raw] < password',
    options: { hash: { type: 'string' }, ...QUIET_OPTION, ...RAW_OPTION },
    run(ctx) {
      const storedHash = requireOpt(ctx.values, 'hash');
      if (!isPasswordHash(storedHash)) {
        throw new UsageError(`malformed --hash (expected output of: ${ctx.prog} password-hash)`);
      }
      const password = readStdinOnly(ctx, 'password');
      return reportVerification(ctx.io, ctx.values, verifyPasswordSync(password, storedHash));
    },
  },

  encrypt: {
    summary: 'Encrypt text with AES-256-GCM',
    usage: 'encrypt (--key-env VAR | --key-file PATH) [--raw] [TEXT|-]',
    options: { ...KEY_OPTIONS, ...RAW_OPTION },
    run(ctx) {
      const key = readAesKey(ctx);
      writeLine(ctx.io, encrypt(readInput(ctx), key));
      return EXIT_OK;
    },
  },

  decrypt: {
    summary: 'Decrypt text produced by "encrypt"',
    usage: 'decrypt (--key-env VAR | --key-file PATH) [CIPHERTEXT|-]',
    options: { ...KEY_OPTIONS, ...RAW_OPTION },
    run(ctx) {
      const key = readAesKey(ctx);
      const ciphertext = readInput(ctx).trim();
      let plaintext: string;
      try {
        plaintext = decrypt(ciphertext, key);
      } catch {
        ctx.io.stderr(`${ctx.prog}: decryption failed (wrong key, or data is corrupted or tampered with)\n`);
        return EXIT_FAILED;
      }
      writeLine(ctx.io, plaintext);
      return EXIT_OK;
    },
  },

  'rsa-encrypt': {
    summary: 'Encrypt a small secret with an RSA public key (RSA-OAEP)',
    usage: 'rsa-encrypt --public-key PATH [--raw] [TEXT|-]',
    options: { 'public-key': { type: 'string' }, ...RAW_OPTION },
    run(ctx) {
      const publicKey = readKeyObject(ctx, 'public-key');
      const data = readInput(ctx);
      let encrypted: string;
      try {
        encrypted = encryptAsymmetric(data, publicKey);
      } catch {
        throw new UsageError('input too large for RSA (max ~446 bytes for 4096-bit keys); use "encrypt" for large data');
      }
      writeLine(ctx.io, encrypted);
      return EXIT_OK;
    },
  },

  'rsa-decrypt': {
    summary: 'Decrypt text produced by "rsa-encrypt"',
    usage: 'rsa-decrypt --private-key PATH [CIPHERTEXT|-]',
    options: { 'private-key': { type: 'string' }, ...RAW_OPTION },
    run(ctx) {
      const privateKey = readKeyObject(ctx, 'private-key');
      const ciphertext = readInput(ctx).trim();
      let plaintext: string;
      try {
        plaintext = decryptAsymmetric(ciphertext, privateKey);
      } catch {
        ctx.io.stderr(`${ctx.prog}: decryption failed (wrong key, or data is corrupted)\n`);
        return EXIT_FAILED;
      }
      writeLine(ctx.io, plaintext);
      return EXIT_OK;
    },
  },

  sign: {
    summary: 'Sign text with an RSA private key (SHA-256)',
    usage: 'sign --private-key PATH [--raw] [TEXT|-]',
    options: { 'private-key': { type: 'string' }, ...RAW_OPTION },
    run(ctx) {
      const privateKey = readKeyObject(ctx, 'private-key');
      writeLine(ctx.io, sign(readInput(ctx), privateKey));
      return EXIT_OK;
    },
  },

  verify: {
    summary: 'Verify a signature with an RSA public key (exit 0 = valid, 1 = invalid)',
    usage: 'verify --public-key PATH --signature BASE64 [-q] [--raw] [TEXT|-]',
    options: { 'public-key': { type: 'string' }, signature: { type: 'string' }, ...QUIET_OPTION, ...RAW_OPTION },
    run(ctx) {
      const publicKey = readKeyObject(ctx, 'public-key');
      const signature = requireOpt(ctx.values, 'signature');
      let isValid: boolean;
      try {
        isValid = verify(readInput(ctx), signature, publicKey);
      } catch {
        isValid = false;
      }
      return reportVerification(ctx.io, ctx.values, isValid);
    },
  },

  'keygen aes': {
    summary: 'Generate a 256-bit AES key (hex)',
    usage: 'keygen aes',
    options: {},
    run(ctx) {
      expectPositionals(ctx.positionals, 0);
      writeLine(ctx.io, generateAESKey().toString('hex'));
      return EXIT_OK;
    },
  },

  'keygen rsa': {
    summary: 'Generate an RSA-4096 key pair into a directory',
    usage: 'keygen rsa --out-dir DIR [--force]',
    options: { 'out-dir': { type: 'string' }, force: { type: 'boolean' } },
    run(ctx) {
      expectPositionals(ctx.positionals, 0);
      const outDir = requireOpt(ctx.values, 'out-dir');
      const privatePath = join(outDir, 'private.pem');
      const publicPath = join(outDir, 'public.pem');

      if (ctx.values.force !== true) {
        for (const path of [privatePath, publicPath]) {
          if (existsSync(path)) throw new UsageError(`${path} already exists (use --force to overwrite)`);
        }
      }

      const { publicKey, privateKey } = generateRSA();
      mkdirSync(outDir, { recursive: true, mode: 0o700 });
      writeFileSync(privatePath, privateKey, { mode: 0o600 });
      chmodSync(privatePath, 0o600); // mode above is ignored when overwriting an existing file
      writeFileSync(publicPath, publicKey, { mode: 0o644 });

      writeLine(ctx.io, `private key: ${privatePath}`);
      writeLine(ctx.io, `public key:  ${publicPath}`);
      return EXIT_OK;
    },
  },

  'random hex': {
    summary: 'Generate random bytes as hex (default 32 bytes)',
    usage: 'random hex [BYTES]',
    options: {},
    run(ctx) {
      expectPositionals(ctx.positionals, 1);
      const bytes = parseIntArg(ctx.positionals[0], 'BYTES', 32);
      if (bytes <= 0) throw new UsageError('<BYTES> must be a positive integer');
      writeLine(ctx.io, generateHex(bytes));
      return EXIT_OK;
    },
  },

  'random uuid': {
    summary: 'Generate a random UUID v4',
    usage: 'random uuid',
    options: {},
    run(ctx) {
      expectPositionals(ctx.positionals, 0);
      writeLine(ctx.io, generateUUID());
      return EXIT_OK;
    },
  },

  'random int': {
    summary: 'Generate a random integer in [MIN, MAX) — MAX is exclusive',
    usage: 'random int MIN MAX',
    options: {},
    run(ctx) {
      expectPositionals(ctx.positionals, 2);
      const min = parseIntArg(ctx.positionals[0], 'MIN');
      const max = parseIntArg(ctx.positionals[1], 'MAX');
      if (max <= min) throw new UsageError('<MAX> must be greater than <MIN>');
      writeLine(ctx.io, String(generateInt(min, max)));
      return EXIT_OK;
    },
  },

  'random string': {
    summary: 'Generate random strings for tokens/API keys (default length 32)',
    usage: 'random string [LENGTH] [--charset letters,numbers,special] [--count N]',
    options: { charset: { type: 'string' }, count: { type: 'string', short: 'n' } },
    run(ctx) {
      expectPositionals(ctx.positionals, 1);
      const length = parseIntArg(ctx.positionals[0], 'LENGTH', 32);
      const count = parseIntArg(stringOpt(ctx.values, 'count'), 'count', 1);

      const charsets = (stringOpt(ctx.values, 'charset') ?? 'letters,numbers').split(',').map((s) => s.trim());
      const unknown = charsets.filter((c) => !['letters', 'numbers', 'special'].includes(c));
      if (unknown.length > 0) {
        throw new UsageError(`unknown charset "${unknown.join(',')}" (use: letters, numbers, special)`);
      }

      let strings: string[];
      try {
        strings = generateSecureStrings(count, length, {
          letters: charsets.includes('letters'),
          numbers: charsets.includes('numbers'),
          specialCharacters: charsets.includes('special'),
        });
      } catch (error) {
        throw new UsageError((error as Error).message);
      }
      writeLine(ctx.io, strings.join('\n'));
      return EXIT_OK;
    },
  },
};

const GROUPS = new Set(['keygen', 'random']);

/** Both names are installed as bins and point at the same entry file. */
export const PROGRAM_NAMES = ['secret-kit', 'secure-kit'] as const;
export const DEFAULT_PROGRAM_NAME = PROGRAM_NAMES[0];

export interface RunOptions {
  version?: string;
  programName?: string;
}

// ---------- help ----------

function mainHelp(prog: string): string {
  const width = Math.max(...Object.keys(COMMANDS).map((name) => name.length));
  const lines = Object.entries(COMMANDS).map(([name, cmd]) => `  ${name.padEnd(width)}  ${cmd.summary}`);
  return [
    `Usage: ${prog} <command> [options] [input]`,
    '',
    'Commands:',
    ...lines,
    '',
    'Input:   TEXT argument, or stdin when omitted or "-". One trailing newline',
    '         on stdin is removed unless --raw is given.',
    'Secrets: never passed as values; read from --*-env VAR or --*-file PATH.',
    'Exit:    0 success, 1 verification/decryption failed, 2 usage error.',
    '',
    `Run "${prog} <command> --help" for command details.`,
    `Alias: ${PROGRAM_NAMES.filter((name) => name !== prog).join(', ')} (same command).`,
    '',
  ].join('\n');
}

function commandHelp(prog: string, cmd: Command): string {
  return `Usage: ${prog} ${cmd.usage}\n\n${cmd.summary}\n`;
}

// ---------- entry ----------

export function run(argv: string[], io: CliIO, options: RunOptions = {}): number {
  const { version = 'dev', programName: prog = DEFAULT_PROGRAM_NAME } = options;
  const [first, second] = argv;

  if (first === undefined || first === 'help' || first === '--help' || first === '-h') {
    io.stdout(mainHelp(prog));
    return first === undefined ? EXIT_USAGE : EXIT_OK;
  }
  if (first === '--version' || first === '-v') {
    writeLine(io, version);
    return EXIT_OK;
  }

  const isGroup = GROUPS.has(first);
  const name = isGroup && second !== undefined ? `${first} ${second}` : first;
  const rest = argv.slice(isGroup ? 2 : 1);
  const command = COMMANDS[name];

  if (!command) {
    io.stderr(`${prog}: unknown command "${name}"\n\n${mainHelp(prog)}`);
    return EXIT_USAGE;
  }

  if (rest.includes('--help') || rest.includes('-h')) {
    io.stdout(commandHelp(prog, command));
    return EXIT_OK;
  }

  try {
    const { values, positionals } = parseArgs({
      args: rest,
      options: command.options,
      allowPositionals: true,
      strict: true,
    });
    return command.run({ values: values as Values, positionals, io, prog });
  } catch (error) {
    const isUsage = error instanceof UsageError || (error as NodeJS.ErrnoException).code?.startsWith('ERR_PARSE_ARGS');
    if (!isUsage) throw error;
    io.stderr(`${prog}: ${(error as Error).message}\nUsage: ${prog} ${command.usage}\n`);
    return EXIT_USAGE;
  }
}

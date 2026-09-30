import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, statSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { run, CliIO, EXIT_OK, EXIT_FAILED, EXIT_USAGE } from '../src/cli/run.js';
import { hash } from '../src/index.js';

interface Result {
  code: number;
  stdout: string;
  stderr: string;
}

function cli(argv: string[], options: { stdin?: string; env?: NodeJS.ProcessEnv } = {}): Result {
  let stdout = '';
  let stderr = '';
  const io: CliIO = {
    readStdin: () => options.stdin,
    stdout: (text) => (stdout += text),
    stderr: (text) => (stderr += text),
    env: options.env ?? {},
  };
  const code = run(argv, io, '9.9.9');
  return { code, stdout, stderr };
}

const out = (result: Result) => result.stdout.trimEnd();

describe('CLI: general', () => {
  it('prints help and version', () => {
    expect(cli(['--help']).stdout).toContain('Usage: secret-kit <command>');
    expect(out(cli(['--version']))).toBe('9.9.9');
    expect(cli(['random', 'uuid', '--help']).stdout).toContain('Usage: secret-kit random uuid');
  });

  it('exits with usage error for no args, unknown commands and unknown options', () => {
    expect(cli([]).code).toBe(EXIT_USAGE);
    expect(cli(['bogus']).code).toBe(EXIT_USAGE);
    expect(cli(['hash', '--nope', 'x']).code).toBe(EXIT_USAGE);
  });

  it('errors when there is no argument and stdin is a terminal', () => {
    const result = cli(['hash']);
    expect(result.code).toBe(EXIT_USAGE);
    expect(result.stderr).toContain('no input');
  });
});

describe('CLI: hash / hmac', () => {
  it('hashes an argument and stdin, stripping one trailing newline from stdin', () => {
    expect(out(cli(['hash', 'hello']))).toBe(hash('hello'));
    expect(out(cli(['hash'], { stdin: 'hello\n' }))).toBe(hash('hello'));
    expect(out(cli(['hash', '--raw'], { stdin: 'hello\n' }))).toBe(hash('hello\n'));
    expect(out(cli(['hash', '-a', 'sha512', 'hello']))).toHaveLength(128);
  });

  it('rejects unsupported algorithms', () => {
    expect(cli(['hash', '-a', 'md5', 'x']).code).toBe(EXIT_USAGE);
  });

  it('signs and verifies with a secret from an env var', () => {
    const env = { WEBHOOK_SECRET: 's3cr3t' };
    const signature = out(cli(['hmac', '--secret-env', 'WEBHOOK_SECRET', 'payload'], { env }));

    const valid = cli(['hmac-verify', '--secret-env', 'WEBHOOK_SECRET', '--signature', signature, 'payload'], { env });
    expect(valid.code).toBe(EXIT_OK);
    expect(out(valid)).toBe('valid');

    const tampered = cli(['hmac-verify', '--secret-env', 'WEBHOOK_SECRET', '--signature', signature, 'changed'], { env });
    expect(tampered.code).toBe(EXIT_FAILED);

    const wrongLength = cli(['hmac-verify', '-q', '--secret-env', 'WEBHOOK_SECRET', '--signature', 'abc', 'payload'], { env });
    expect(wrongLength.code).toBe(EXIT_FAILED);
    expect(wrongLength.stderr).toBe('');
  });

  it('requires exactly one secret source', () => {
    expect(cli(['hmac', 'x']).code).toBe(EXIT_USAGE);
    expect(cli(['hmac', '--secret-env', 'MISSING', 'x']).code).toBe(EXIT_USAGE);
    expect(cli(['hmac', '--secret-env', 'A', '--secret-file', '/x', 'x'], { env: { A: 'a' } }).code).toBe(EXIT_USAGE);
  });
});

describe('CLI: passwords', () => {
  it('hashes and verifies a password from stdin', () => {
    const storedHash = out(cli(['password-hash'], { stdin: 'P@ssw0rd\n' }));
    expect(storedHash).toMatch(/^[0-9a-f]{32}:[0-9a-f]{128}$/);

    expect(cli(['password-verify', '--hash', storedHash], { stdin: 'P@ssw0rd\n' }).code).toBe(EXIT_OK);
    expect(cli(['password-verify', '--hash', storedHash], { stdin: 'wrong\n' }).code).toBe(EXIT_FAILED);
  });

  it('refuses passwords passed as arguments', () => {
    const result = cli(['password-hash', 'P@ssw0rd']);
    expect(result.code).toBe(EXIT_USAGE);
    expect(result.stderr).toContain('stdin');
  });

  it('reports a malformed stored hash as a usage error instead of crashing', () => {
    expect(cli(['password-verify', '--hash', 'abcd:1234'], { stdin: 'x' }).code).toBe(EXIT_USAGE);
  });
});

describe('CLI: AES encryption', () => {
  it('round-trips with a key from env and rejects the wrong key', () => {
    const env = { DATA_KEY: out(cli(['keygen', 'aes'])), OTHER_KEY: out(cli(['keygen', 'aes'])) };
    expect(env.DATA_KEY).toMatch(/^[0-9a-f]{64}$/);

    const ciphertext = out(cli(['encrypt', '--key-env', 'DATA_KEY'], { stdin: 'db-password\n', env }));
    expect(out(cli(['decrypt', '--key-env', 'DATA_KEY'], { stdin: `${ciphertext}\n`, env }))).toBe('db-password');

    const wrong = cli(['decrypt', '--key-env', 'OTHER_KEY', ciphertext], { env });
    expect(wrong.code).toBe(EXIT_FAILED);
    expect(wrong.stdout).toBe('');
  });

  it('rejects keys that are not 32 bytes of hex', () => {
    expect(cli(['encrypt', '--key-env', 'K', 'x'], { env: { K: 'abc' } }).code).toBe(EXIT_USAGE);
  });
});

describe('CLI: RSA', () => {
  let dir: string;
  let privateKey: string;
  let publicKey: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'secret-kit-'));
    expect(cli(['keygen', 'rsa', '--out-dir', dir]).code).toBe(EXIT_OK);
    privateKey = join(dir, 'private.pem');
    publicKey = join(dir, 'public.pem');
  });

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('writes the private key with owner-only permissions and refuses to overwrite', () => {
    expect(statSync(privateKey).mode & 0o777).toBe(0o600);
    expect(cli(['keygen', 'rsa', '--out-dir', dir]).code).toBe(EXIT_USAGE);
  });

  it('signs and verifies', () => {
    const signature = out(cli(['sign', '--private-key', privateKey, 'release-v1']));
    expect(cli(['verify', '--public-key', publicKey, '--signature', signature, 'release-v1']).code).toBe(EXIT_OK);
    expect(cli(['verify', '--public-key', publicKey, '--signature', signature, 'tampered']).code).toBe(EXIT_FAILED);
  });

  it('encrypts and decrypts', () => {
    const ciphertext = out(cli(['rsa-encrypt', '--public-key', publicKey, 'api-token']));
    expect(out(cli(['rsa-decrypt', '--private-key', privateKey, ciphertext]))).toBe('api-token');
  });

  it('rejects invalid key files', () => {
    const bad = join(dir, 'bad.pem');
    writeFileSync(bad, 'not a key');
    expect(cli(['sign', '--private-key', bad, 'x']).code).toBe(EXIT_USAGE);
    expect(cli(['sign', '--private-key', join(dir, 'missing.pem'), 'x']).code).toBe(EXIT_USAGE);
  });
});

describe('CLI: random', () => {
  it('generates hex, uuid and ints', () => {
    expect(out(cli(['random', 'hex']))).toMatch(/^[0-9a-f]{64}$/);
    expect(out(cli(['random', 'hex', '8']))).toMatch(/^[0-9a-f]{16}$/);
    expect(out(cli(['random', 'uuid']))).toMatch(/^[0-9a-f-]{36}$/);

    const value = Number(out(cli(['random', 'int', '1', '3'])));
    expect([1, 2]).toContain(value);
  });

  it('generates strings with the requested charset and count', () => {
    const lines = out(cli(['random', 'string', '16', '--charset', 'numbers', '-n', '3'])).split('\n');
    expect(lines).toHaveLength(3);
    for (const line of lines) expect(line).toMatch(/^\d{16}$/);
  });

  it('rejects invalid numbers and charsets', () => {
    expect(cli(['random', 'hex', '0']).code).toBe(EXIT_USAGE);
    expect(cli(['random', 'int', '5', '5']).code).toBe(EXIT_USAGE);
    expect(cli(['random', 'int', '1', 'x']).code).toBe(EXIT_USAGE);
    expect(cli(['random', 'string', '--charset', 'emoji']).code).toBe(EXIT_USAGE);
  });
});

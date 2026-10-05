# SecureKit

A lightweight, secure, and easy-to-use cryptographic toolkit for Node.js, built on top of the native `crypto` module.

## Features

- **Zero runtime crypto dependencies** — thin, typed wrappers over Node.js's native `crypto` module.
- **Dual build** — ships both CommonJS and ESM with TypeScript declarations.
- **Command line tool** — `secret-kit` (alias `secure-kit`) exposes the same features to shell scripts and CI. See [Command Line Interface](#command-line-interface-secret-kit).
- **Documented internals** — see [How It Works](#how-it-works) for what each function does step by step.

| Category | Functions | Algorithm / Details |
| :--- | :--- | :--- |
| Hashing | `hash` | SHA-256 (default) or SHA-512, hex output |
| HMAC | `hmac` | HMAC-SHA-256 (default) or HMAC-SHA-512, hex output |
| Password hashing | `hashPassword`, `verifyPassword`, `needsRehash` (+ `*Sync` variants) | Argon2id (64 MiB, t=3, p=4), 16-byte random salt, 32-byte tag, NFKC normalization, timing-safe compare. Output: PHC string `$argon2id$v=19$m=…,t=…,p=…$salt$hash`. Still verifies 1.x scrypt hashes |
| Symmetric encryption | `encrypt`, `decrypt` | AES-256-GCM (authenticated), 12-byte random IV. Output: `iv:authTag:ciphertext` (hex) |
| Asymmetric encryption | `encryptAsymmetric`, `decryptAsymmetric` | RSA-OAEP with SHA-256, base64 output |
| Digital signatures | `sign`, `verify` | SHA-256 signatures (RSA), base64 output |
| Key management | `generateAESKey`, `deriveKey`, `generateRSA`, `generateEd25519` | 256-bit AES key, scrypt key derivation, RSA-4096 and Ed25519 key pairs (PEM) |
| Secure random | `generateBytes`, `generateHex`, `generateUUID`, `generateInt`, `generateSecureString`, `generateSecureStrings` | CSPRNG-backed; secure strings use unbiased `randomInt` selection |

## Installation

```bash
npm install @datdm198x/secure-kit
```

Requires **Node.js 24.7 or later** (for the built-in `crypto.argon2`).

## Quick Start

```typescript
import { hash, encrypt, decrypt, generateAESKey } from '@datdm198x/secure-kit';

// Hash data
const hashed = hash('my data'); // Result: '4c4b...7b' (hex string)

// Symmetric Encryption
const key = generateAESKey(); // Result: <Buffer 8b 2a ...>

// convert the key to a hex string for storage or transmission
const keyHex = key.toString('hex'); // Result: '8b2a...e1'

// convert the hex string back to a Buffer for decryption
const keyBuffer = Buffer.from(keyHex, 'hex');

// Encrypt data using the generated key
const encrypted = encrypt('my secret data', keyBuffer); // Result: 'iv:authTag:ciphertext' (hex)

// Decrypt data using the same key
const decrypted = decrypt(encrypted, keyBuffer); // Result: 'my secret data'

console.log('Hashed:', hashed);
console.log('Key:', keyHex);
console.log('Encrypted:', encrypted);
console.log('Decrypted:', decrypted);
```

## Hash & HMAC
Provides robust one-way hashing and HMAC functionality.

### Hash
**Common Usecase:**
- Data Integrity: Verify files or data have not been tampered with.
- Data Mapping: Generate consistent, unique identifiers without exposing the original data.

```typescript
import { hash } from '@datdm198x/secure-kit';
const hashed = hash('my data'); // Result: '4c4b...7b'
```

### HMAC
**Common Usecase:**
- API Request Signing: Verify that an API request originated from a trusted source (e.g., verifying a webhook payload like `{"message": "transfer", "amount": "100$"}`).

```typescript
import { hmac } from '@datdm198x/secure-kit';
import { timingSafeEqual } from 'crypto';

// 1. Webhook received (Header convention: often 'X-Signature' or 'X-Hub-Signature')
const payload = '{"message": "transfer", "amount": "100$"}';
const receivedSignature = '...signature_from_header...'; // Extracted from request header

// 2. Calculate expected signature locally using shared secret
const expectedSignature = hmac(payload, 'mySecretKey'); // Result: 'a1b2...c3'

// 3. Verify: Compare received vs expected (use timingSafeEqual to prevent timing attacks)
const isVerified = timingSafeEqual(
  Buffer.from(receivedSignature, 'hex'),
  Buffer.from(expectedSignature, 'hex')
); // Result: true or false
```


## How It Works

Every feature is a thin wrapper over Node.js's native `crypto` module. This section explains what each function does internally, what its output looks like, and the limits you should know about.

### Hash (`hash`)

1. The input string is encoded as UTF-8.
2. It is hashed with SHA-256 (default) or SHA-512 via `crypto.createHash`.
3. The digest is returned as lowercase hex: 64 characters for SHA-256, 128 for SHA-512.

- **Deterministic:** the same input always gives the same output, so it is good for integrity checks and for hashing *high-entropy* values such as random API keys.
- **Not for passwords or low-entropy data** (emails, phone numbers): SHA-2 is fast, so attackers can try billions of guesses per second. Use `hashPassword` or `hmac` instead.

### HMAC (`hmac`)

1. The secret string (UTF-8) becomes the HMAC key.
2. `crypto.createHmac` computes HMAC-SHA-256 (default) or HMAC-SHA-512 over the UTF-8 input (RFC 2104).
3. The tag is returned as hex.

- Only someone holding the secret can produce a matching tag, so it proves the message came from a secret holder and wasn't modified.
- Because the output depends on the secret, it also works as a **blind index**: you can look up `hmac(email, secret)` without storing a hash that can be brute-forced from email lists.
- `hmac` only *computes* the tag. When checking a received tag, compare with `crypto.timingSafeEqual` (as in the HMAC example) so response time doesn't leak how many characters matched. The CLI's `hmac-verify` already does this.

### Password hashing (`hashPassword`, `verifyPassword`, `needsRehash`)

**Hashing** (`hashPassword(password, options?)`):

1. **Validate:** the password must be a non-empty string. It is normalized to Unicode NFKC (NIST SP 800-63B), so visually identical input typed on different keyboards gives the same result. After normalization it must be at most 1024 UTF-8 bytes.
2. **Resolve cost:** defaults are `memory: 65536` KiB (64 MiB), `passes: 3`, `parallelism: 4`. Custom values are checked against the OWASP minimum (19 MiB, 2 passes) and a safety cap (4 GiB, 64 passes, 64 lanes).
3. **Salt:** 16 random bytes from `crypto.randomBytes`, unique per hash, so two users with the same password get different hashes and precomputed (rainbow) tables don't work.
4. **Derive:** `crypto.argon2('argon2id', …)` produces a 32-byte tag. Argon2id fills `memory` KiB of RAM and makes `passes` passes over it, so each guess costs an attacker the same memory and time it costs you. GPUs and ASICs can't run many guesses in parallel cheaply.
5. **Encode:** the result is a standard PHC string, with salt and tag in unpadded base64:

   ```
   $argon2id$v=19$m=65536,t=3,p=4$<salt>$<tag>
    algorithm  ver  cost params    16 B   32 B
   ```

   Because the cost parameters travel with the hash, you can raise them later without breaking existing hashes.

**Verifying** (`verifyPassword(password, storedHash)`):

1. **Parse** the stored hash strictly:
   - An Argon2id PHC string is accepted if its parameters are within safe bounds (memory ≤ 4 GiB, passes ≤ 64, salt 8–64 bytes, tag 16–64 bytes). The upper bounds stop a crafted hash from making verification consume unbounded memory or CPU. Weaker-but-valid hashes from other Argon2id libraries are accepted.
   - A legacy 1.x scrypt hash (`32 hex chars : 128 hex chars`) is also accepted.
   - Anything else returns `false`.
2. **Re-derive** with the stored salt and parameters:
   - Argon2id: the password is normalized the same way as when hashing.
   - Legacy scrypt (N=16384, r=8, p=1, 64-byte key): the raw password is used, because 1.x didn't normalize.
3. **Compare** the derived tag with the stored tag using `crypto.timingSafeEqual`, which takes the same time whether the first byte or the last byte differs.
4. **Never throw** for bad input: a wrong password, an empty or over-long password, or a malformed hash all return `false`.

**Upgrading** (`needsRehash(storedHash, options?)`) returns `true` when the stored hash is legacy scrypt, malformed, or uses Argon2id parameters different from the target. Call it right after a *successful* `verifyPassword`, while you still have the plaintext, and store a fresh `hashPassword` result. Users are migrated gradually as they log in.

**Async vs sync:** `hashPassword` / `verifyPassword` run Argon2 on libuv's thread pool and return Promises, so a server keeps handling other requests during the ~30 ms of hashing. `hashPasswordSync` / `verifyPasswordSync` block the event loop; use them only in scripts and CLIs. The thread pool has 4 threads by default (`UV_THREADPOOL_SIZE`), which caps concurrent hashes per process.

`isPasswordHash(value)` tells you whether a string is in a format `verifyPassword` understands, without doing any hashing.

### Symmetric encryption (`encrypt`, `decrypt`)

**Encrypting** (`encrypt(text, key)`):

1. The key must be exactly 32 bytes (AES-256). `generateAESKey()` creates one; Node throws for any other length.
2. A fresh random 12-byte IV (nonce) is generated for every call. Encrypting the same text twice gives different output.
3. AES-256-GCM encrypts the UTF-8 text and computes a 16-byte authentication tag over the ciphertext.
4. Output: `ivHex:authTagHex:ciphertextHex`. The ciphertext is the same length as the input.

**Decrypting** (`decrypt(payload, key)`):

1. Split on `:` and decode the IV, tag, and ciphertext from hex.
2. Decrypt and verify the tag. If the key is wrong or **any** byte of the payload was modified, GCM authentication fails and `decrypt` **throws**. You never get silently corrupted plaintext.

- **Key limit:** with random 12-byte IVs, NIST recommends at most about 2³² encryptions per key. Rotate keys well before that.
- **Key storage:** the key is the only secret. Keep it in a secret manager (AWS Secrets Manager, Vault, KMS), never in source code or in the same database as the ciphertext.

### Asymmetric encryption (`encryptAsymmetric`, `decryptAsymmetric`)

1. `encryptAsymmetric(text, publicKey)` encrypts the UTF-8 text with RSA using OAEP padding and SHA-256 (`crypto.publicEncrypt`). OAEP adds randomness, so the same text encrypts differently each time. Output is base64.
2. `decryptAsymmetric(payload, privateKey)` reverses it with `crypto.privateDecrypt`. Only the private-key holder can decrypt. A wrong key or modified payload makes it throw.

- **Size limit:** a 4096-bit key holds at most 446 bytes of plaintext (512 − 2×32 − 2). For larger data use *hybrid encryption*: encrypt the data with `encrypt` under a fresh AES key, then encrypt only that AES key with `encryptAsymmetric`.
- Both functions take `KeyObject`s. Convert PEM strings with `crypto.createPublicKey` / `crypto.createPrivateKey`.

### Digital signatures (`sign`, `verify`)

1. `sign(text, privateKey)` hashes the UTF-8 text with SHA-256 and signs the digest with the RSA private key (`crypto.sign`, RSASSA-PKCS1-v1_5 padding). Output is base64; a 4096-bit key gives a 512-byte (684-character) signature.
2. `verify(text, signature, publicKey)` recomputes the SHA-256 digest and checks it against the signature with the public key. It returns `true` only if the text is byte-for-byte unchanged **and** was signed by the matching private key.

- Anyone with the public key can verify, so signatures prove authorship to third parties. (An HMAC can only be checked by someone who holds the shared secret.)
- Signatures don't hide the data. Combine with encryption if it is confidential.
- `sign`/`verify` work with RSA keys only. They always pass `'sha256'`, which Node rejects for Ed25519 keys.

### Key management (`generateAESKey`, `deriveKey`, `generateRSA`, `generateEd25519`)

| Function | How it works | Output |
| :--- | :--- | :--- |
| `generateAESKey()` | 32 bytes from `crypto.randomBytes` | `Buffer` (store it as hex or base64) |
| `deriveKey(password, salt, keyLength = 32)` | scrypt with Node's defaults (N=16384, r=8, p=1). The same password and salt always give the same key, so store the salt (not secret, but unique per key) next to the ciphertext. Intended for turning a passphrase into an *encryption key*. For storing passwords, use `hashPassword`. | `Buffer` of `keyLength` bytes |
| `generateRSA()` | `crypto.generateKeyPairSync('rsa', { modulusLength: 4096 })`, public exponent 65537. Takes about 0.5–2 s, depending on hardware. | `{ publicKey, privateKey }` as PEM strings (SPKI / unencrypted PKCS#8) |
| `generateEd25519()` | `crypto.generateKeyPairSync('ed25519')` | `{ publicKey, privateKey }` as PEM strings |

The private key PEM is **not** password-protected. Store it with restricted permissions (the CLI's `keygen rsa` writes it with mode `0600`) or in a secret manager.

### Secure random (`generateBytes`, `generateHex`, `generateUUID`, `generateInt`, `generateSecureString`, `generateSecureStrings`)

All functions use the operating system's cryptographically secure random number generator (CSPRNG) through Node's `crypto`. Never use `Math.random()` for security values.

| Function | How it works |
| :--- | :--- |
| `generateBytes(n)` / `generateHex(n)` | `crypto.randomBytes(n)`. Hex output is `2n` characters. 32 bytes = 256 bits of entropy. |
| `generateUUID()` | `crypto.randomUUID()`: an RFC 9562 version 4 UUID with 122 random bits. |
| `generateInt(min, max)` | `crypto.randomInt`, uniform over `[min, max)` (max is **exclusive**). It uses rejection sampling, so there is no modulo bias. `max − min` must be below 2⁴⁸. |
| `generateSecureString(length, options)` | Builds a character pool from the enabled sets (52 letters, 10 digits, 29 symbols), then picks each character with `crypto.randomInt(pool.length)` (uniform, no modulo bias). Entropy is `length × log₂(pool size)`: for example, 20 letters and digits ≈ 119 bits. |
| `generateSecureStrings(count, length, options)` | Calls `generateSecureString` `count` times independently. |

### Command line tool (`secret-kit` / `secure-kit`)

1. **Parse:** the first word(s) pick the command (`keygen` and `random` take a sub-command). Options are parsed with Node's `util.parseArgs` in strict mode, so unknown options are rejected.
2. **Read input:** from the last argument, or stdin when it is omitted or `-`. One trailing newline is stripped unless `--raw` is given.
3. **Read secrets safely:**
   - AES keys and HMAC secrets come only from `--key-env` / `--secret-env` (an environment variable) or `--key-file` / `--secret-file`, never from option values, which would show up in `ps` and shell history. AES keys must be 64 hex characters.
   - Passwords are read **only** from stdin.
4. **Call the library:** the commands call the same functions documented above. Password commands use the `*Sync` variants, which is fine for a short-lived process. `password-verify` checks the `--hash` format before reading stdin.
5. **Report:** the result goes to stdout; errors go to stderr. Exit codes: `0` success, `1` verification or decryption failed, `2` usage error. Scripts can branch on exit codes alone with `-q`.

## Examples

### Password Hashing
Securely hash passwords with Argon2id. The salt and cost parameters are stored inside the hash string.

```typescript
import { hashPassword, verifyPassword, needsRehash } from '@datdm198x/secure-kit';

const password = 'mySecretPassword123';

// 1. Hash the password for storage
const hashedPassword = await hashPassword(password);
// Result: '$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>'

// 2. Verify a password attempt against the stored hash
const isMatch = await verifyPassword(password, hashedPassword); // Result: true

// 3. After a successful login, upgrade old or weaker hashes
if (isMatch && needsRehash(hashedPassword)) {
  // save await hashPassword(password) in place of the old hash
}
```

| Detail | Behavior |
| :--- | :--- |
| Cost | Defaults: `memory: 65536` (KiB = 64 MiB), `passes: 3`, `parallelism: 4`. Override with `hashPassword(pw, { memory, passes, parallelism })`. Minimums: 19456 KiB and 2 passes (OWASP). Each hash takes ~30 ms and uses `memory` KiB of RAM while running, so size your pods for concurrent logins. |
| Input | Passwords are NFKC-normalized. Empty or over 1024 bytes → `hashPassword` throws `RangeError`; `verifyPassword` returns `false`. |
| Errors | `verifyPassword` never throws for bad input. Malformed or unsupported hashes return `false`. |
| Sync | `hashPasswordSync` / `verifyPasswordSync` block the event loop. Use them in scripts and CLIs, not in servers. |
| Interop | Standard PHC format, so hashes from other Argon2id libraries (e.g. `argon2` on npm, `argon2-cffi`) verify too. |

#### Migrating from 1.x (scrypt)

- `hashPassword` and `verifyPassword` are now **async** (return Promises). Add `await`, or switch to the `*Sync` variants.
- Existing `salt:hash` scrypt hashes **still verify**. `needsRehash` returns `true` for them, so users are moved to Argon2id at their next login (see above). No bulk migration is needed.
- Widen your `password_hash` column if it is fixed-width: new hashes are about 100 characters.

### Symmetric Encryption (AES-256-GCM)
Best for encrypting data at rest. Authenticated encryption ensures integrity and confidentiality.

```typescript
import { generateAESKey, encrypt, decrypt } from '@datdm198x/secure-kit';

// 1. Generate a secure 256-bit key
const key = generateAESKey(); // Result: <Buffer 8b 2a ...>

// convert the key to a hex string for storage or transmission
const keyHex = key.toString('hex'); // Result: '8b2a...e1'

// convert the hex string back to a Buffer for decryption
const keyBuffer = Buffer.from(keyHex, 'hex');

// 2. Encrypt data using the generated key
const encrypted = encrypt('my secret data', keyBuffer); // Result: 'iv:authTag:ciphertext' (hex)

// 3. Decrypt data using the same key
const decrypted = decrypt(encrypted, keyBuffer); // Result: 'my secret data'

console.log('Key:', keyHex);
console.log('Encrypted:', encrypted);
console.log('Decrypted:', decrypted);
```

### Asymmetric Encryption (RSA-OAEP)
Best for securely sharing data between parties.

```typescript
import { createPrivateKey, createPublicKey } from 'crypto';
import { generateRSA, encryptAsymmetric, decryptAsymmetric } from '@datdm198x/secure-kit';

// 1. Generate key pair (PEM strings) and load them as KeyObjects
const pem = generateRSA(); // Result: { publicKey: '-----BEGIN PUBLIC KEY-----...', privateKey: '-----BEGIN PRIVATE KEY-----...' }
const publicKey = createPublicKey(pem.publicKey);
const privateKey = createPrivateKey(pem.privateKey);
const data = 'Sensitive data for RSA';

// 2. Encrypt with Public Key
const encrypted = encryptAsymmetric(data, publicKey); // Result: '...'

// 3. Decrypt with Private Key
const decrypted = decryptAsymmetric(encrypted, privateKey); // Result: 'Sensitive data for RSA'
```

### Digital Signature (RSA + SHA256)
Best for verifying data authenticity and integrity.

```typescript
import { createPrivateKey, createPublicKey } from 'crypto';
import { generateRSA, sign, verify } from '@datdm198x/secure-kit';

// 1. Generate key pair (PEM strings) and load them as KeyObjects
const pem = generateRSA();
const publicKey = createPublicKey(pem.publicKey);
const privateKey = createPrivateKey(pem.privateKey);
const data = 'Document to sign';

// 2. Sign with Private Key
const signature = sign(data, privateKey); // Result: '...'

// 3. Verify with Public Key
const isValid = verify(data, signature, publicKey); // Result: true
```

### Secure Random Generation
Cryptographically secure random data generation.

```typescript
import {
  generateBytes,
  generateHex,
  generateUUID,
  generateInt,
  generateSecureString,
  generateSecureStrings,
} from '@datdm198x/secure-kit';

// Generate random bytes (returns Buffer)
const bytes = generateBytes(16); 
// Result: <Buffer 3e 8f 1a 2b 4c 5d 6e 7f 8a 9b 0c 1d 2e 3f 4a 5b>

// Generate a random hex string
const hex = generateHex(16);
// Result: '3e8f1a2b4c5d6e7f8a9b0c1d2e3f4a5b'

// Generate a random UUID
const uuid = generateUUID();
// Result: '550e8400-e29b-41d4-a716-446655440000'

// Generate a random integer in [min, max) — max is exclusive
const int = generateInt(1, 101); // 1..100
// Result: 42

// Generate a secure random string (e.g. for API keys/tokens)
const secureString = generateSecureString(20, {
  letters: true,
  numbers: true,
  specialCharacters: true,
});
// Result: 'aZ3!k9Lp_2Qw@8Mv$1x('

// Generate several secure strings at once
const secureStrings = generateSecureStrings(5, 20, { specialCharacters: true });
// Result: ['aZ3!k9Lp...', 'Qw8Mv$1x...', ...]
```

## End-to-End Use Case: Securing a User Account Service

This walkthrough follows one user from sign-up to a signed data export, and shows where each SecureKit feature fits.

| Step | What happens | SecureKit functions |
| :---: | :--- | :--- |
| 0 | Provision secrets once | `generateAESKey`, `generateSecureString` |
| 1 | Load and validate secrets at startup | — |
| 2 | Register a user | `generateUUID`, `hashPassword`, `encrypt`, `hmac` |
| 3 | Log in | `hmac`, `verifyPassword` |
| 4 | Read protected profile data | `decrypt` |
| 5 | Issue an API key | `generateSecureString`, `hash` |
| 6 | Authenticate an API request | `hash` |
| 7 | Send and verify a signed webhook | `hmac` + `timingSafeEqual` |
| 8 | Share a signed, encrypted export with a partner | `generateRSA`, `sign`, `verify`, `encryptAsymmetric`, `decryptAsymmetric` |

### Step 0 — Provision secrets (one-time, outside the app)

> **Goal:** create the three secrets the app needs. **You need:** nothing. **You get:** three values to put in your secret manager.

Run this once, then store the values in a secret manager such as AWS Secrets Manager or Vault. Don't commit them to Git or `.env` files.

```typescript
import { generateAESKey, generateSecureString } from '@datdm198x/secure-kit';

// 1. AES-256 key for encrypting personal data (Step 2 and Step 4).
//    generateAESKey() returns a 32-byte Buffer; convert it to hex so it can be stored as text.
console.log('DATA_ENCRYPTION_KEY =', generateAESKey().toString('hex')); // 64 hex chars (32 bytes)

// 2. Secret for the email lookup index (Step 2 and Step 3).
console.log('EMAIL_INDEX_SECRET  =', generateSecureString(48));

// 3. Secret shared with the webhook receiver for signing payloads (Step 7).
console.log('WEBHOOK_SECRET      =', generateSecureString(48));

// Copy these values into your secret manager, then delete the terminal output.
```

> Use a **separate secret for each purpose**. Then a leak of one (for example, the webhook secret shared with a partner) doesn't expose your encrypted data.

### Step 1 — Load and validate secrets at startup

> **Goal:** load the secrets from Step 0 when the app starts. **You need:** the secrets as environment variables (for example, injected from your secret manager). **You get:** `dataKey`, `EMAIL_INDEX_SECRET`, `WEBHOOK_SECRET`, used by the later steps.

Fail fast if a secret is missing or malformed.

```typescript
// Helper: read an environment variable, or stop the app if it's missing.
// Failing at startup is safer than failing later in the middle of a user request.
function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required secret: ${name}`);
  return value;
}

// 1. Load the AES key and convert it from hex text back to a Buffer.
const dataKey = Buffer.from(requireEnv('DATA_ENCRYPTION_KEY'), 'hex');

// 2. Check the key is exactly 32 bytes. AES-256 won't work with any other length.
if (dataKey.length !== 32) throw new Error('DATA_ENCRYPTION_KEY must be 32 bytes (64 hex chars).');

// 3. Load the HMAC secrets. These are used as plain strings.
const EMAIL_INDEX_SECRET = requireEnv('EMAIL_INDEX_SECRET');
const WEBHOOK_SECRET = requireEnv('WEBHOOK_SECRET');
```

### Step 2 — Register a user

> **Goal:** save a new user safely. **You need:** email, password, and phone from the sign-up form. **You get:** a `UserRecord` that doesn't contain the password, phone, or email in readable form.

Each field is protected in a different way, depending on how you need to use it later:

- **Password** → `hashPassword` (salted Argon2id). You only ever need to *check* it, never read it back. Never store it in plaintext or encrypt it.
- **Phone number (PII)** → `encrypt` (AES-256-GCM), because you need to read it back later.
- **Email lookup** → `hmac` creates a *blind index*. You can look users up by email without storing a plain, searchable hash. A plain `hash(email)` can be brute-forced from lists of known emails; an HMAC needs the secret.

```typescript
import { generateUUID, hashPassword, encrypt, hmac } from '@datdm198x/secure-kit';

// Shape of what goes into the database. No field contains readable personal data.
type UserRecord = {
  id: string;             // random UUID, safe to expose
  emailIndex: string;     // HMAC of the normalized email, used only for lookups
  passwordHash: string;   // '$argon2id$...', used only for verification
  phoneEncrypted: string; // 'iv:authTag:ciphertext', can be decrypted with dataKey
  apiKeyHash?: string;    // set in Step 5
};

// Stand-in for your database table (keyed by user id).
const users = new Map<string, UserRecord>();

// Normalize the email (trim spaces, lowercase) before the HMAC.
// Without this, 'Alice@Example.com' and 'alice@example.com' would give different indexes
// and the user couldn't log in with a different capitalization.
const emailIndexOf = (email: string) => hmac(email.trim().toLowerCase(), EMAIL_INDEX_SECRET);

async function register(email: string, password: string, phone: string): Promise<UserRecord> {
  const user: UserRecord = {
    id: generateUUID(),                      // 1. Random, unguessable user id.
    emailIndex: emailIndexOf(email),         // 2. Lookup key for login (Step 3).
    passwordHash: await hashPassword(password), // 3. Slow, salted, one-way. Can't be reversed.
    phoneEncrypted: encrypt(phone, dataKey), // 4. Reversible, but only with dataKey (Step 4).
  };

  // 5. Save it. The plaintext email, password, and phone are never stored.
  users.set(user.id, user);
  return user;
}

// Example: register Alice.
const user = await register('Alice@Example.com', 'correct horse battery staple', '+84 912 345 678');
```

### Step 3 — Log in

> **Goal:** check a login attempt. **You need:** email and password from the login form. **You get:** the `UserRecord` on success, or `null` on failure.

```typescript
import { hashPassword, verifyPassword, needsRehash } from '@datdm198x/secure-kit';

async function login(email: string, password: string): Promise<UserRecord | null> {
  // 1. Compute the same blind index as in Step 2. The same email always gives the same index.
  const index = emailIndexOf(email);

  // 2. Find the user by index. In a real database: SELECT ... WHERE email_index = $1
  const found = [...users.values()].find((u) => u.emailIndex === index);

  // 3. Check the password against the stored hash.
  //    verifyPassword re-hashes the attempt with the stored salt and compares in constant time.
  // 4. Return the same result for "unknown email" and "wrong password"
  //    so attackers can't tell which accounts exist.
  if (!found || !(await verifyPassword(password, found.passwordHash))) return null;

  // 5. Transparently upgrade old (1.x scrypt) or weaker hashes while we have the plaintext.
  if (needsRehash(found.passwordHash)) {
    found.passwordHash = await hashPassword(password);
  }
  return found;
}

// Capitalization doesn't matter because the email is normalized.
await login('alice@example.com', 'correct horse battery staple'); // Result: UserRecord
await login('alice@example.com', 'wrong password');               // Result: null
```

> Rate-limit login attempts at the API layer. Password hashing slows down brute-force attacks but doesn't stop them.

### Step 4 — Read protected profile data

> **Goal:** show the user their own phone number. **You need:** the stored `phoneEncrypted` and `dataKey` from Step 1. **You get:** the original plaintext.

```typescript
import { decrypt } from '@datdm198x/secure-kit';

// Only decrypt after you've checked the caller is allowed to see this user's data.

// decrypt() reads the IV and auth tag from the stored string, checks the data wasn't changed,
// and then returns the original text.
const phone = decrypt(user.phoneEncrypted, dataKey); // Result: '+84 912 345 678'
```

If the ciphertext was tampered with, or the wrong key is used, `decrypt` throws. Catch the error and return a generic message instead of the raw error.

### Step 5 — Issue an API key

> **Goal:** give the user a key for programmatic access. **You need:** a logged-in user. **You get:** a key to show the user once, and a hash to store.

Generate a high-entropy key and show it to the user **once**. Store only its hash. A fast SHA-256 is fine here because the key is random and long. Passwords are low-entropy, which is why they need Argon2id instead.

```typescript
import { generateSecureString, hash } from '@datdm198x/secure-kit';

// 1. Generate 40 random letters and digits. The 'sk_' prefix makes the key easy to recognize
//    (for example, by secret scanners if it leaks into a Git repo).
const apiKey = `sk_${generateSecureString(40)}`;

// 2. Store only the SHA-256 hash. If the database leaks, the real keys are still safe.
user.apiKeyHash = hash(apiKey);

// 3. Return apiKey to the user in the HTTP response, once. Never log it.
//    If they lose it, issue a new key. You can't recover the old one.
```

### Step 6 — Authenticate an API request

> **Goal:** find out which user sent an API request. **You need:** the key from the request header (for example, `Authorization: Bearer sk_...`). **You get:** the `UserRecord`, or `null` if the key is invalid.

```typescript
function authenticateApiKey(presentedKey: string): UserRecord | null {
  // 1. Hash the key the client sent, the same way as in Step 5.
  const presentedHash = hash(presentedKey);

  // 2. Find the user with that hash. In a real database: SELECT ... WHERE api_key_hash = $1
  // 3. No match means an invalid or revoked key. Respond with 401 Unauthorized.
  return [...users.values()].find((u) => u.apiKeyHash === presentedHash) ?? null;
}
```

In a real database, look up by `apiKeyHash` using an index; don't scan every row.

### Step 7 — Send and verify a signed webhook

> **Goal:** let a receiver confirm a webhook really came from you and wasn't changed. **You need:** `WEBHOOK_SECRET`, known to both sides. **You get:** a signature header (sender), and `true`/`false` (receiver).

**Sender** signs the exact raw body:

```typescript
// 1. Build the payload string. Sign this exact string, not the object.
const payload = JSON.stringify({ event: 'user.created', userId: user.id });

// 2. Compute the HMAC signature with the shared secret.
const signature = hmac(payload, WEBHOOK_SECRET);

// 3. Send the payload as the request body and the signature as a header:
//    POST payload with header: X-Signature: <signature>
```

**Receiver** recomputes the signature over the raw body and compares in constant time. Check the length first, because `timingSafeEqual` throws when the buffers differ in length.

```typescript
import { timingSafeEqual } from 'crypto';

// rawBody must be the body exactly as received, before JSON parsing.
// Parsing and re-serializing can change spacing or key order and break the signature.
function verifyWebhook(rawBody: string, receivedSignature: string): boolean {
  // 1. Compute what the signature should be for this body.
  const expected = Buffer.from(hmac(rawBody, WEBHOOK_SECRET), 'hex');

  // 2. Convert the signature from the X-Signature header into bytes.
  const received = Buffer.from(receivedSignature, 'hex');

  // 3. Check the length first (timingSafeEqual throws on different lengths),
  //    then compare in constant time so attackers can't guess the signature byte by byte.
  return received.length === expected.length && timingSafeEqual(received, expected);
}

verifyWebhook(payload, signature); // Result: true  → process the event
verifyWebhook(payload, 'forged');  // Result: false → reject with 401
```

> To prevent replay attacks, include a timestamp or nonce in the signed payload and reject old or duplicate deliveries.

### Step 8 — Share a signed, encrypted export with a partner

> **Goal:** send a partner a report they can trust, plus a secret only they can read. **You need:** an RSA key pair for each side, with public keys exchanged. **You get:** a signature and an encrypted secret you can send over any channel.

- You **sign** with *your* private key, so the partner can prove the data came from you.
- You **encrypt** with the *partner's* public key, so only the partner can read it.

```typescript
import { createPrivateKey, createPublicKey } from 'crypto';
import { generateRSA, sign, verify, encryptAsymmetric, decryptAsymmetric } from '@datdm198x/secure-kit';

// 1. Each party generates their own key pair once and publishes only the public key.
//    Private keys stay with their owner, in a secret manager.
//    (Both pairs are generated here only so the example runs in one file.)
const ours = generateRSA();
const partner = generateRSA();

// 2. generateRSA() returns PEM strings. Load them as KeyObjects, which the sign/encrypt functions expect.
const ourPrivate = createPrivateKey(ours.privateKey);
const ourPublic = createPublicKey(ours.publicKey);
const partnerPrivate = createPrivateKey(partner.privateKey);
const partnerPublic = createPublicKey(partner.publicKey);

// --- Our side ---
// 3. Build the report and sign it with OUR private key. Only we can create this signature.
const report = JSON.stringify({ totalUsers: users.size, generatedAt: new Date().toISOString() });
const reportSignature = sign(report, ourPrivate);

// 4. Encrypt a small secret with the PARTNER's public key. Only the partner can decrypt it.
const sessionSecret = encryptAsymmetric('export-password-123', partnerPublic);

// 5. Send report, reportSignature, and sessionSecret to the partner (any channel is fine).

// --- Partner side ---
// 6. Check the signature with OUR public key. This proves we sent it and nothing was changed.
verify(report, reportSignature, ourPublic);        // Result: true (false if the report was altered)

// 7. Decrypt the secret with the PARTNER's own private key.
decryptAsymmetric(sessionSecret, partnerPrivate);  // Result: 'export-password-123'
```

> RSA-OAEP with a 4096-bit key can only encrypt small payloads (about 446 bytes). For large data, encrypt it with `encrypt` (AES) using a fresh `generateAESKey()`, then encrypt only that AES key with `encryptAsymmetric`.

### Summary: which tool for which job

| Need | Use | Why |
| :--- | :--- | :--- |
| Store a password | `hashPassword` / `verifyPassword` / `needsRehash` | Slow, memory-hard, salted, one-way |
| Store data you must read back | `encrypt` / `decrypt` | Confidentiality and tamper detection |
| Look up by a sensitive value | `hmac` (blind index) | Deterministic but needs a secret |
| Store a random token or API key | `hash` | Fast is OK because the input is high-entropy |
| Prove a message came from a shared-secret holder | `hmac` | Symmetric authentication |
| Prove authorship to anyone | `sign` / `verify` | Public verification |
| Send a secret to one recipient | `encryptAsymmetric` | Only the private-key holder can decrypt |
| IDs, tokens, keys | `generateUUID`, `generateSecureString`, `generateAESKey` | CSPRNG-backed |

## Command Line Interface (`secret-kit`)

The package ships a `secret-kit` command so you can use the same crypto from shell scripts, CI jobs, and the terminal.

The same command is also installed as **`secure-kit`**, matching the package name. Both names behave identically; the examples below use `secret-kit`.

```bash
# Use without installing
npx -p @datdm198x/secure-kit secret-kit --help
npx @datdm198x/secure-kit --help            # the package-name alias works directly with npx

# Or install globally
npm install -g @datdm198x/secure-kit
secret-kit --help
secure-kit --help                          # same command
```

### Conventions (important for scripts)

| Topic | Behavior |
| :--- | :--- |
| **Input** | Pass it as the last argument, or pipe it on stdin (when the argument is omitted or `-`). |
| **Trailing newline** | One trailing newline on stdin is removed, so `echo "x" \| ...` and `printf "x" \| ...` give the same result. Use `--raw` to keep stdin exactly as-is. |
| **Secrets** | Never passed as option values, because they would leak into `ps` and shell history. AES keys and HMAC secrets come from `--key-env VAR` / `--secret-env VAR` or `--key-file PATH` / `--secret-file PATH`. Passwords are **only** read from stdin. |
| **Output** | The result goes to stdout followed by a newline. Errors go to stderr. |
| **Exit codes** | `0` success · `1` verification failed or decryption failed · `2` usage error (bad option, missing input or secret) |
| **Verify commands** | Print `valid` (stdout) or `invalid` (stderr). Add `-q` / `--quiet` to rely on the exit code only. |

### Commands

| Command | Purpose |
| :--- | :--- |
| `hash [-a sha256\|sha512] [TEXT]` | Hash text |
| `hmac --secret-env VAR [-a ...] [TEXT]` | Create an HMAC signature |
| `hmac-verify --signature HEX --secret-env VAR [TEXT]` | Verify an HMAC signature |
| `password-hash < password` | Hash a password (Argon2id) |
| `password-verify --hash HASH < password` | Check a password against a hash (Argon2id, or a 1.x scrypt hash) |
| `encrypt --key-env VAR [TEXT]` | Encrypt with AES-256-GCM |
| `decrypt --key-env VAR [CIPHERTEXT]` | Decrypt `encrypt` output |
| `rsa-encrypt --public-key PATH [TEXT]` | Encrypt a small secret with RSA-OAEP |
| `rsa-decrypt --private-key PATH [CIPHERTEXT]` | Decrypt `rsa-encrypt` output |
| `sign --private-key PATH [TEXT]` | Sign with RSA (SHA-256) |
| `verify --public-key PATH --signature B64 [TEXT]` | Verify an RSA signature |
| `keygen aes` | Generate a 256-bit AES key (hex) |
| `keygen rsa --out-dir DIR [--force]` | Generate an RSA-4096 key pair (`private.pem` is written with mode `600`) |
| `random hex [BYTES]` | Random hex (default 32 bytes) |
| `random uuid` | Random UUID v4 |
| `random int MIN MAX` | Random integer in `[MIN, MAX)` (MAX is exclusive) |
| `random string [LENGTH] [--charset letters,numbers,special] [-n COUNT]` | Random tokens (default 32 letters and numbers) |

Run `secret-kit <command> --help` for the exact options of each command. Wherever `--*-env VAR` is shown, you can use `--*-file PATH` instead.

### Shell examples

**Generate secrets for a new environment**

```bash
# AES key for encrypting data. Store it in your secret manager, don't commit it.
secret-kit keygen aes > data.key && chmod 600 data.key

# A 48-character token for an HMAC/webhook secret.
secret-kit random string 48

# Five one-time recovery codes, digits only.
secret-kit random string 10 --charset numbers -n 5
```

**Encrypt and decrypt a value**

```bash
export DATA_KEY="$(cat data.key)"   # or load it from your secret manager

# Encrypt: the plaintext comes from stdin, so it doesn't appear in `ps` output.
CIPHERTEXT=$(printf '%s' "$DB_PASSWORD" | secret-kit encrypt --key-env DATA_KEY)

# Decrypt: exit code 1 means the key is wrong or the data was tampered with.
printf '%s' "$CIPHERTEXT" | secret-kit decrypt --key-env DATA_KEY
```

**Verify a webhook in a script**

```bash
# $BODY is the raw request body, $SIGNATURE is the X-Signature header value.
if printf '%s' "$BODY" | secret-kit hmac-verify -q --secret-env WEBHOOK_SECRET --signature "$SIGNATURE"; then
  echo "trusted webhook"
else
  echo "rejected: bad signature" >&2
  exit 1
fi
```

**Hash and check a password**

```bash
# Read the password without echoing it, then pipe it in on stdin (never as an argument).
read -rs PASSWORD
HASH=$(printf '%s' "$PASSWORD" | secret-kit password-hash)

# Single-quote the hash if you paste it literally: it contains '$'.
printf '%s' "$PASSWORD" | secret-kit password-verify -q --hash "$HASH" && echo "match"
```

**Sign a release file and verify it**

```bash
# One-time setup: keep keys/private.pem secret, publish keys/public.pem.
secret-kit keygen rsa --out-dir ./keys

# Sign the file's checksum (binary files are checksummed with shasum; see Limitations).
shasum -a 256 release.tar.gz > release.sha256
SIG=$(secret-kit sign --private-key ./keys/private.pem < release.sha256)

# Anyone with the public key can verify it.
secret-kit verify --public-key ./keys/public.pem --signature "$SIG" < release.sha256
```

### Limitations

- **Text only.** Input is read as UTF-8 text, so binary files aren't hashed byte-for-byte. For a binary file's checksum, use `shasum -a 256 file` (or `sha256sum`), then sign or HMAC that text with `secret-kit`.
- **RSA encryption holds only small payloads** (about 446 bytes). Use `encrypt` for anything larger.
- **Signing is RSA only.** `sign` and `verify` currently don't work with Ed25519 keys.

## FAQ

### Why use AES-256-GCM?
AES-GCM provides both confidentiality and data integrity (authentication), making it the industry standard for symmetric encryption.

### Are my keys secure?
This library generates keys using Node.js's cryptographically secure random number generator (`randomBytes`). Ensure you store your keys securely (e.g., environment variables, HashiCorp Vault, AWS KMS) and never hardcode them.

### Why Argon2id for passwords?
Argon2id won the Password Hashing Competition and is OWASP's first choice for password storage. It is memory-hard, which makes GPU/ASIC cracking expensive, and the hybrid `id` variant also resists side-channel attacks. This library uses Node's built-in `crypto.argon2`, so there is no native add-on to compile. (`deriveKey` still uses scrypt; it derives encryption keys, not stored password hashes.)

## Changelog

| Version | Changes |
| :--- | :--- |
| 2.0.0 (unreleased) | **Breaking.** Password hashing moves from scrypt to Argon2id (Node's built-in `crypto.argon2`). `hashPassword` / `verifyPassword` are now async; `hashPasswordSync`, `verifyPasswordSync`, `needsRehash`, and `isPasswordHash` added. `verifyPassword` returns `false` instead of throwing for malformed hashes. 1.x scrypt hashes still verify. Requires Node.js ≥ 24.7. |
| 1.2.0 | The CLI is also installed as `secure-kit`, so `npx @datdm198x/secure-kit ...` works directly. |
| 1.1.0 | Added the `secret-kit` CLI. |
| 1.0.6 | Added `generateSecureString` / `generateSecureStrings`. |

## Testing

Comprehensive test coverage is maintained for all cryptographic operations.

| Test File | Status | Tests |
| :--- | :--- | :---: |
| `hash.test.ts` | ✅ Passed | 3 |
| `password.test.ts` | ✅ Passed | 16 |
| `encrypt.test.ts` | ✅ Passed | 5 |
| `random.test.ts` | ✅ Passed | 10 |
| `key.test.ts` | ✅ Passed | 4 |
| `cli.test.ts` | ✅ Passed | 22 |
| **Total** | **✅ 100%** | **60** |

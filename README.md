# SecureKit

A lightweight, secure, and easy-to-use cryptographic toolkit for Node.js, built on top of the native `crypto` module.

## Installation

```bash
npm install @datdm198x/secure-kit
```

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
const encrypted = encrypt('my secret data', keyBuffer); // Result: '{"iv":"...","content":"...","authTag":"..."}'

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


## Examples

### Password Hashing
Securely hash passwords with salt automatically included.

```typescript
import { hashPassword, verifyPassword } from '@datdm198x/secure-kit';

const password = 'mySecretPassword123';

// 1. Hash the password for storage
const hashedPassword = hashPassword(password); // Result: '$scrypt$n=16384...'

// 2. Verify a password attempt against the stored hash
const isMatch = verifyPassword(password, hashedPassword); // Result: true
```

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
const encrypted = encrypt('my secret data', keyBuffer); // Result: '{"iv":"...","content":"...","authTag":"..."}'

// 3. Decrypt data using the same key
const decrypted = decrypt(encrypted, keyBuffer); // Result: 'my secret data'

console.log('Key:', keyHex);
console.log('Encrypted:', encrypted);
console.log('Decrypted:', decrypted);
```

### Asymmetric Encryption (RSA-OAEP)
Best for securely sharing data between parties.

```typescript
import { generateRSA, encryptAsymmetric, decryptAsymmetric } from '@datdm198x/secure-kit';

// 1. Generate key pair
const { publicKey, privateKey } = generateRSA(); // Result: { publicKey: '...', privateKey: '...' }
const data = 'Sensitive data for RSA';

// 2. Encrypt with Public Key
const encrypted = encryptAsymmetric(data, publicKey); // Result: '...'

// 3. Decrypt with Private Key
const decrypted = decryptAsymmetric(encrypted, privateKey); // Result: 'Sensitive data for RSA'
```

### Digital Signature (RSA + SHA256)
Best for verifying data authenticity and integrity.

```typescript
import { generateRSA, sign, verify } from '@datdm198x/secure-kit';

// 1. Generate key pair
const { publicKey, privateKey } = generateRSA();
const data = 'Document to sign';

// 2. Sign with Private Key
const signature = sign(data, privateKey); // Result: '...'

// 3. Verify with Public Key
const isValid = verify(data, signature, publicKey); // Result: true
```

### Secure Random Generation
Cryptographically secure random data generation.

```typescript
import { generateBytes, generateHex, generateUUID, generateInt } from '@datdm198x/secure-kit';

// Generate random bytes (returns Buffer)
const bytes = generateBytes(16); 
// Result: <Buffer 3e 8f 1a 2b 4c 5d 6e 7f 8a 9b 0c 1d 2e 3f 4a 5b>

// Generate a random hex string
const hex = generateHex(16);
// Result: '3e8f1a2b4c5d6e7f8a9b0c1d2e3f4a5b'

// Generate a random UUID
const uuid = generateUUID();
// Result: '550e8400-e29b-41d4-a716-446655440000'

// Generate a random integer between min and max (inclusive)
const int = generateInt(1, 100);
// Result: 42
```

## FAQ

### Why use AES-256-GCM?
AES-GCM provides both confidentiality and data integrity (authentication), making it the industry standard for symmetric encryption.

### Are my keys secure?
This library generates keys using Node.js's cryptographically secure random number generator (`randomBytes`). Ensure you store your keys securely (e.g., environment variables, HashiCorp Vault, AWS KMS) and never hardcode them.

### Why Scrypt for passwords?
Scrypt is a memory-hard password-based key derivation function (KDF) that is highly resistant to brute-force attacks using specialized hardware (ASICs/GPUs).

## Testing

Comprehensive test coverage is maintained for all cryptographic operations.

| Test File | Status | Tests |
| :--- | :--- | :---: |
| `hash.test.ts` | ✅ Passed | 4 |
| `encrypt.test.ts` | ✅ Passed | 5 |
| `random.test.ts` | ✅ Passed | 4 |
| `key.test.ts` | ✅ Passed | 4 |
| **Total** | **✅ 100%** | **17** |

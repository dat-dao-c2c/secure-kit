# SecureKit

A lightweight, secure, and easy-to-use cryptographic toolkit for Node.js, built on top of the native `crypto` module.

## Installation

```bash
npm install @datdm198x/secure-kit
```

## Quick Start

```typescript
import { hash, encrypt, generateAESKey } from '@datdm198x/secure-kit';

// Hash data
const hashed = hash('my data');

// Symmetric Encryption
const key = generateAESKey();
const encrypted = encrypt('my secret data', key);
```

## Examples

### Password Hashing
Securely hash passwords with salt automatically included.

```typescript
import { hashPassword, verifyPassword } from '@datdm198x/secure-kit';

const password = 'mySecretPassword123';

// 1. Hash the password for storage
const hashedPassword = hashPassword(password);

// 2. Verify a password attempt against the stored hash
const isMatch = verifyPassword(password, hashedPassword);
```

### Symmetric Encryption (AES-256-GCM)
Best for encrypting data at rest. Authenticated encryption ensures integrity and confidentiality.

```typescript
import { generateAESKey, encrypt, decrypt } from '@datdm198x/secure-kit';

// 1. Generate a secure 256-bit key
const key = generateAESKey();
const data = 'Sensitive data to encrypt';

// 2. Encrypt
const encrypted = encrypt(data, key);

// 3. Decrypt
const decrypted = decrypt(encrypted, key);
```

### Asymmetric Encryption (RSA-OAEP)
Best for securely sharing data between parties.

```typescript
import { generateRSA, encryptAsymmetric, decryptAsymmetric } from '@datdm198x/secure-kit';

// 1. Generate key pair
const { publicKey, privateKey } = generateRSA();
const data = 'Sensitive data for RSA';

// 2. Encrypt with Public Key
const encrypted = encryptAsymmetric(data, publicKey);

// 3. Decrypt with Private Key
const decrypted = decryptAsymmetric(encrypted, privateKey);
```

### Digital Signature (RSA + SHA256)
Best for verifying data authenticity and integrity.

```typescript
import { generateRSA, sign, verify } from '@datdm198x/secure-kit';

// 1. Generate key pair
const { publicKey, privateKey } = generateRSA();
const data = 'Document to sign';

// 2. Sign with Private Key
const signature = sign(data, privateKey);

// 3. Verify with Public Key
const isValid = verify(data, signature, publicKey);
```

## FAQ

### Why use AES-256-GCM?
AES-GCM provides both confidentiality and data integrity (authentication), making it the industry standard for symmetric encryption.

### Are my keys secure?
This library generates keys using Node.js's cryptographically secure random number generator (`randomBytes`). Ensure you store your keys securely (e.g., environment variables, HashiCorp Vault, AWS KMS) and never hardcode them.

### Why Scrypt for passwords?
Scrypt is a memory-hard password-based key derivation function (KDF) that is highly resistant to brute-force attacks using specialized hardware (ASICs/GPUs).

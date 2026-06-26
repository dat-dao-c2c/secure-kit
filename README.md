# SecureKit

A lightweight, secure, and easy-to-use cryptographic toolkit for Node.js, built on top of the native `crypto` module.

## Installation

```bash
npm install @datdm198x/secure-kit
```

## Quick Start

```typescript
import { hash, encrypt, generateAESKey } from '@datdm198x/secure-kit';

// 1. Hashing
const hashed = hash('my data');

// 2. Symmetric Encryption
const key = generateAESKey();
const encrypted = encrypt('my secret data', key);
```

## Hash
Provides robust one-way hashing and HMAC functionality.
- `hash(data, algorithm)`: Supported algorithms: 'sha256', 'sha512'.
- `hmac(data, secret, algorithm)`

## Encrypt
Supports both symmetric and asymmetric encryption.
- Symmetric (AES-256-GCM): `encrypt(data, key)` - Authenticated encryption.
- Asymmetric (RSA-OAEP): `encryptAsymmetric(data, publicKey)`

## Decrypt
- Symmetric: `decrypt(encryptedData, key)`
- Asymmetric: `decryptAsymmetric(encryptedData, privateKey)`

## Password
Secure password hashing using Scrypt with automatic salting.
- `hashPassword(password)`: Returns `salt:hash`.
- `verifyPassword(password, hashedPassword)`: Timing-safe verification.

## Random
Cryptographically secure random data generation.
- `generateBytes(size)`
- `generateHex(size)`
- `generateUUID()`
- `generateInt(min, max)`

## Signature
Digital signatures for data authenticity.
- `sign(data, privateKey)`
- `verify(data, signature, publicKey)`

## FAQ

### Why use AES-256-GCM?
AES-GCM provides both confidentiality and data integrity (authentication), making it the industry standard for symmetric encryption.

### Are my keys secure?
This library generates keys using Node.js's cryptographically secure random number generator (`randomBytes`). Ensure you store your keys securely (e.g., environment variables, HashiCorp Vault, AWS KMS) and never hardcode them.

### Why Scrypt for passwords?
Scrypt is a memory-hard password-based key derivation function (KDF) that is highly resistant to brute-force attacks using specialized hardware (ASICs/GPUs).


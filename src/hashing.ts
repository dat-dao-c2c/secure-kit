import { createHash, createHmac } from 'crypto';

export function hash(data: string, algorithm: 'sha256' | 'sha512' = 'sha256'): string {
  return createHash(algorithm).update(data).digest('hex');
}

export function hmac(data: string, secret: string, algorithm: 'sha256' | 'sha512' = 'sha256'): string {
  return createHmac(algorithm, secret).update(data).digest('hex');
}

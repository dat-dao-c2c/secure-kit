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

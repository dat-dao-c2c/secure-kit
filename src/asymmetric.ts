import * as crypto from 'crypto';

/**
 * Encrypts data using RSA public key.
 */
export function encryptAsymmetric(data: string, publicKey: crypto.KeyObject): string {
  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(data, 'utf8')
  ).toString('base64');
}

/**
 * Decrypts data using RSA private key.
 */
export function decryptAsymmetric(encryptedData: string, privateKey: crypto.KeyObject): string {
  return crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(encryptedData, 'base64')
  ).toString('utf8');
}

/**
 * Signs data using private key.
 */
export function sign(data: string, privateKey: crypto.KeyObject): string {
  return crypto.sign('sha256', Buffer.from(data, 'utf8'), privateKey).toString('base64');
}

/**
 * Verifies signed data using public key.
 */
export function verify(data: string, signature: string, publicKey: crypto.KeyObject): boolean {
  return crypto.verify(
    'sha256',
    Buffer.from(data, 'utf8'),
    publicKey,
    Buffer.from(signature, 'base64')
  );
}

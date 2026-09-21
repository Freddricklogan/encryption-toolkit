/** Digests and HMAC on Web Crypto, with constant-time verification. */
import { equalBytes, fromHex, utf8 } from './encoding.js';

const subtle = globalThis.crypto.subtle;
export const HASHES = ['SHA-256', 'SHA-384', 'SHA-512'];

export async function digest(algorithm, bytes) {
  if (!HASHES.includes(algorithm)) throw new Error(`unsupported hash ${algorithm}`);
  return new Uint8Array(await subtle.digest(algorithm, bytes));
}
export const digestText = (algorithm, text) => digest(algorithm, utf8(text));

export async function hmacSign(algorithm, keyBytes, message) {
  const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: algorithm }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', key, message));
}
export async function hmacVerify(algorithm, keyBytes, message, tagHex) {
  let tag;
  try {
    tag = fromHex(tagHex);
  } catch {
    return false;
  }
  return equalBytes(await hmacSign(algorithm, keyBytes, message), tag);
}

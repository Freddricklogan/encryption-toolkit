/**
 * AES-256-GCM with PBKDF2 or HKDF key derivation, associated data, and AES-KW key wrapping.
 * Everything runs on Web Crypto (browser or Node 22). Tested against NIST GCM, RFC 5869,
 * RFC 3394 and RFC 6070 vectors in tests/symmetric.test.js.
 */
import { concat, fromBase64Url, fromUtf8, toBase64Url, utf8 } from './encoding.js';

const subtle = globalThis.crypto.subtle;
export const PBKDF2_ITERATIONS = 600000; // OWASP 2023 guidance for PBKDF2-HMAC-SHA256

export async function importRawAesKey(rawKey, usages = ['encrypt', 'decrypt']) {
  return subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, usages);
}

export async function pbkdf2(passphrase, salt, { iterations = PBKDF2_ITERATIONS, hash = 'SHA-256', length = 256 } = {}) {
  const material = await subtle.importKey('raw', utf8(passphrase), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash }, material, length));
}

/** HKDF-Extract-and-Expand (RFC 5869) via Web Crypto. */
export async function hkdf(ikm, { salt = new Uint8Array(0), info = new Uint8Array(0), hash = 'SHA-256', length = 32 } = {}) {
  const material = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', salt, info, hash }, material, length * 8));
}

export async function aesGcmEncrypt(rawKey, iv, plaintext, aad) {
  const key = await importRawAesKey(rawKey, ['encrypt']);
  const params = { name: 'AES-GCM', iv, tagLength: 128 };
  if (aad && aad.byteLength) params.additionalData = aad;
  return new Uint8Array(await subtle.encrypt(params, key, plaintext));
}

export async function aesGcmDecrypt(rawKey, iv, ciphertext, aad) {
  const key = await importRawAesKey(rawKey, ['decrypt']);
  const params = { name: 'AES-GCM', iv, tagLength: 128 };
  if (aad && aad.byteLength) params.additionalData = aad;
  return new Uint8Array(await subtle.decrypt(params, key, ciphertext));
}

/** AES-KW (RFC 3394): wrap a raw key with a key-encryption key. */
export async function wrapKey(kekRaw, keyRaw) {
  const kek = await subtle.importKey('raw', kekRaw, { name: 'AES-KW' }, false, ['wrapKey']);
  const key = await subtle.importKey('raw', keyRaw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  return new Uint8Array(await subtle.wrapKey('raw', key, kek, 'AES-KW'));
}
export async function unwrapKey(kekRaw, wrapped) {
  const kek = await subtle.importKey('raw', kekRaw, { name: 'AES-KW' }, false, ['unwrapKey']);
  const key = await subtle.unwrapKey('raw', wrapped, kek, 'AES-KW', { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  return new Uint8Array(await subtle.exportKey('raw', key));
}

/**
 * Passphrase envelope, versioned and self-describing:
 *   v2.<base64url salt>.<base64url iv>.<base64url aad>.<base64url ciphertext+tag>.<iterations>
 * A random 256-bit data key is wrapped (AES-KW) by the PBKDF2-derived key-encryption key, so
 * changing the passphrase means re-wrapping 40 bytes, not re-encrypting the data.
 *   v2 wire: salt(16) · iv(12) · wrappedKey(40) · aad · ct
 */
export async function sealWithPassphrase(passphrase, plaintextBytes, { aad = new Uint8Array(0), iterations = PBKDF2_ITERATIONS, random = (n) => crypto.getRandomValues(new Uint8Array(n)) } = {}) {
  if (!passphrase) throw new Error('passphrase is required');
  const salt = random(16);
  const iv = random(12);
  const dataKey = random(32);
  const kek = await pbkdf2(passphrase, salt, { iterations });
  const wrapped = await wrapKey(kek, dataKey);
  const ct = await aesGcmEncrypt(dataKey, iv, plaintextBytes, aad);
  return ['v2', toBase64Url(salt), toBase64Url(iv), toBase64Url(wrapped), toBase64Url(aad), toBase64Url(ct), String(iterations)].join('.');
}

export function parseEnvelope(text) {
  const parts = String(text).trim().split('.');
  if (parts.length !== 7 || parts[0] !== 'v2') throw new Error('not a v2 envelope (expected 7 dot-separated fields)');
  const iterations = parseInt(parts[6], 10);
  if (!(iterations >= 1000 && iterations <= 10000000)) throw new Error('iteration count out of range');
  return { salt: fromBase64Url(parts[1]), iv: fromBase64Url(parts[2]), wrapped: fromBase64Url(parts[3]), aad: fromBase64Url(parts[4]), ct: fromBase64Url(parts[5]), iterations };
}

export async function openWithPassphrase(passphrase, envelopeText) {
  const e = parseEnvelope(envelopeText);
  const kek = await pbkdf2(passphrase, e.salt, { iterations: e.iterations });
  let dataKey;
  try {
    dataKey = await unwrapKey(kek, e.wrapped);
  } catch {
    throw new Error('wrong passphrase (key unwrap failed)');
  }
  try {
    return { plaintext: await aesGcmDecrypt(dataKey, e.iv, e.ct, e.aad), aad: e.aad };
  } catch {
    throw new Error('authentication failed: ciphertext or associated data was modified');
  }
}

export const sealText = async (passphrase, text, opts) => sealWithPassphrase(passphrase, utf8(text), { ...opts, aad: opts?.aad ? utf8(opts.aad) : new Uint8Array(0) });
export const openText = async (passphrase, envelope) => {
  const r = await openWithPassphrase(passphrase, envelope);
  return { text: fromUtf8(r.plaintext), aad: fromUtf8(r.aad) };
};
export { concat };

/** RSA-OAEP encryption, RSA-PSS and ECDSA P-256 signatures on Web Crypto. */
const subtle = globalThis.crypto.subtle;

export async function generateRsaOaep(modulusLength = 2048) {
  if (![2048, 3072, 4096].includes(modulusLength)) throw new Error('modulus must be 2048, 3072 or 4096');
  return subtle.generateKey({ name: 'RSA-OAEP', modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
}
export const rsaEncrypt = (publicKey, bytes) => subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, bytes).then((b) => new Uint8Array(b));
export const rsaDecrypt = (privateKey, bytes) => subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, bytes).then((b) => new Uint8Array(b));
/** RSA-OAEP with SHA-256 can encrypt at most k − 2·hLen − 2 bytes: 190 for a 2048-bit modulus. */
export const rsaMaxPlaintext = (modulusLength) => modulusLength / 8 - 2 * 32 - 2;

export async function generateSigningKeys(kind = 'RSA-PSS') {
  if (kind === 'ECDSA') return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  if (kind === 'RSA-PSS') return subtle.generateKey({ name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  throw new Error('kind must be RSA-PSS or ECDSA');
}
const sigParams = (kind) => (kind === 'ECDSA' ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'RSA-PSS', saltLength: 32 });
export const sign = (kind, privateKey, bytes) => subtle.sign(sigParams(kind), privateKey, bytes).then((b) => new Uint8Array(b));
export const verify = (kind, publicKey, signature, bytes) => subtle.verify(sigParams(kind), publicKey, signature, bytes);
export const exportJwk = (key) => subtle.exportKey('jwk', key);

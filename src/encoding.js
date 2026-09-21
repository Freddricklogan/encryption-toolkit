/** Byte encodings. Pure; every function round-trips and rejects malformed input. */
const enc = new TextEncoder();
const dec = new TextDecoder();

export const utf8 = (s) => enc.encode(s);
export const fromUtf8 = (bytes) => dec.decode(bytes);

export function toHex(bytes) {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
}
export function fromHex(hex) {
  const clean = String(hex).replace(/\s+/g, '');
  if (clean.length % 2 || /[^0-9a-f]/i.test(clean)) throw new Error('not a hex string');
  return Uint8Array.from(clean.match(/../g) ?? [], (h) => parseInt(h, 16));
}
export function toBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}
export function fromBase64(b64) {
  const clean = String(b64).replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4) throw new Error('not base64');
  return Uint8Array.from(atob(clean), (c) => c.charCodeAt(0));
}
export function toBase64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromBase64Url(s) {
  const b = String(s).replace(/-/g, '+').replace(/_/g, '/');
  return fromBase64(b + '='.repeat((4 - (b.length % 4)) % 4));
}
export function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(new Uint8Array(p), off);
    off += p.byteLength;
  }
  return out;
}
/** Constant-time byte comparison. */
export function equalBytes(a, b) {
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i += 1) diff |= x[i] ^ y[i];
  return diff === 0;
}

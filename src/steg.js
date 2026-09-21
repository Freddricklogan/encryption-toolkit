/**
 * Least-significant-bit steganography over RGBA pixel data. One bit per colour channel
 * (alpha untouched), a 4-byte magic and a 4-byte length prefix so extraction can tell a carrier
 * with no payload from one with a payload. Survives lossless PNG; any lossy re-encoding
 * (JPEG) destroys it, and the page says so.
 */
import { concat, fromUtf8, utf8 } from './encoding.js';

const MAGIC = utf8('LSB1');

export function capacityBytes(pixelCount) {
  return Math.floor((pixelCount * 3) / 8) - 8;
}

function writeBit(pixels, bitIndex, bit) {
  const idx = Math.floor(bitIndex / 3) * 4 + (bitIndex % 3);
  pixels[idx] = (pixels[idx] & 0xfe) | bit;
}
function readBit(pixels, bitIndex) {
  const idx = Math.floor(bitIndex / 3) * 4 + (bitIndex % 3);
  return pixels[idx] & 1;
}

/** Embeds `payload` (Uint8Array) into a copy of `pixels`; throws if it does not fit. */
export function embed(pixels, payload) {
  const pixelCount = pixels.length / 4;
  if (payload.length > capacityBytes(pixelCount)) throw new Error(`payload of ${payload.length} bytes exceeds capacity ${capacityBytes(pixelCount)}`);
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, payload.length);
  const all = concat(MAGIC, len, payload);
  const out = new Uint8ClampedArray(pixels);
  let bit = 0;
  for (const byte of all) {
    for (let b = 7; b >= 0; b -= 1) {
      writeBit(out, bit, (byte >> b) & 1);
      bit += 1;
    }
  }
  return out;
}

/** Returns the payload or null when no magic header is present or the length is impossible. */
export function extract(pixels) {
  const pixelCount = pixels.length / 4;
  const readByte = (i) => {
    let v = 0;
    for (let b = 0; b < 8; b += 1) v = (v << 1) | readBit(pixels, i * 8 + b);
    return v;
  };
  for (let i = 0; i < 4; i += 1) if (readByte(i) !== MAGIC[i]) return null;
  const len = new DataView(Uint8Array.from([4, 5, 6, 7].map(readByte)).buffer).getUint32(0);
  if (len > capacityBytes(pixelCount)) return null;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i += 1) out[i] = readByte(8 + i);
  return out;
}

export const embedText = (pixels, text) => embed(pixels, utf8(text));
export const extractText = (pixels) => {
  const bytes = extract(pixels);
  return bytes === null ? null : fromUtf8(bytes);
};

/** Fraction of bytes changed by embedding — the visual cost, which is why LSB is "hidden". */
export function changedFraction(before, after) {
  let changed = 0;
  for (let i = 0; i < before.length; i += 1) if (before[i] !== after[i]) changed += 1;
  return changed / before.length;
}

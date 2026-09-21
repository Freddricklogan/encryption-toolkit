import { describe, expect, it } from 'vitest';
import { utf8 } from '../src/encoding.js';
import { capacityBytes, changedFraction, embed, embedText, extract, extractText } from '../src/steg.js';

const carrier = (n) => Uint8ClampedArray.from({ length: n * 4 }, (_, i) => (i * 7919) & 0xff);

describe('LSB steganography', () => {
  it('round-trips text, leaves alpha untouched, and changes only low bits', () => {
    const px = carrier(256 * 256);
    const out = embedText(px, 'hidden in plain sight — ünïcode too');
    expect(extractText(out)).toBe('hidden in plain sight — ünïcode too');
    for (let i = 3; i < px.length; i += 4) expect(out[i]).toBe(px[i]);
    for (let i = 0; i < px.length; i += 1) expect(Math.abs(out[i] - px[i])).toBeLessThanOrEqual(1);
    expect(changedFraction(px, out)).toBeLessThan(0.002);
    expect(px).toEqual(carrier(256 * 256)); // input not mutated
  });
  it('reports capacity and refuses payloads that do not fit', () => {
    expect(capacityBytes(256 * 256)).toBe(24568);
    const small = carrier(32);
    expect(capacityBytes(32)).toBe(4);
    expect(() => embed(small, utf8('12345'))).toThrow(/exceeds capacity/);
    expect(extractText(embed(small, utf8('1234')))).toBe('1234');
  });
  it('returns null on a carrier with no payload and on an impossible length', () => {
    expect(extract(carrier(64))).toBeNull();
    const out = embedText(carrier(64), 'hi');
    // Corrupt the length field to something larger than the capacity.
    const bad = new Uint8ClampedArray(out);
    for (let bit = 32; bit < 64; bit += 1) {
      const idx = Math.floor(bit / 3) * 4 + (bit % 3);
      bad[idx] |= 1;
    }
    expect(extract(bad)).toBeNull();
  });
});

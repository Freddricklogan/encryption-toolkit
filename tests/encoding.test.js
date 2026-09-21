import { describe, expect, it } from 'vitest';
import { concat, equalBytes, fromBase64, fromBase64Url, fromHex, fromUtf8, toBase64, toBase64Url, toHex, utf8 } from '../src/encoding.js';

describe('encodings', () => {
  it('hex and base64 round-trip and reject malformed input', () => {
    const bytes = Uint8Array.from([0, 1, 127, 128, 255]);
    expect(toHex(bytes)).toBe('00017f80ff');
    expect(fromHex('00 01 7F 80 FF')).toEqual(bytes);
    expect(() => fromHex('abc')).toThrow(/hex/);
    expect(() => fromHex('zz')).toThrow(/hex/);
    expect(toBase64(bytes)).toBe('AAF/gP8=');
    expect(fromBase64('AAF/gP8=')).toEqual(bytes);
    expect(() => fromBase64('AAF/gP8')).toThrow(/base64/);
    expect(toBase64Url(bytes)).toBe('AAF_gP8');
    expect(fromBase64Url('AAF_gP8')).toEqual(bytes);
    expect(fromUtf8(utf8('héllo €'))).toBe('héllo €');
  });
  it('concat and constant-time equality', () => {
    expect(concat(Uint8Array.from([1]), Uint8Array.from([2, 3]))).toEqual(Uint8Array.from([1, 2, 3]));
    expect(equalBytes(Uint8Array.from([1, 2]), Uint8Array.from([1, 2]))).toBe(true);
    expect(equalBytes(Uint8Array.from([1, 2]), Uint8Array.from([1, 3]))).toBe(false);
    expect(equalBytes(Uint8Array.from([1]), Uint8Array.from([1, 0]))).toBe(false);
  });
});
